// SPDX-License-Identifier: MIT
//! The group facade: one device, its credential, and the groups it is in.
//!
//! This is the whole group surface — create, generate a key package, join via
//! Welcome, send and receive application messages, add, remove, self-update,
//! export a secret — with the two things a bare OpenMLS client does not do:
//! every leaf identity-checked, and every proposal policy-checked.
//!
//! ## Why a `Client` that owns its groups
//!
//! The C ABI wants opaque handles and no lifetimes crossing the boundary, and
//! Swift, Kotlin and JS all want to hold one object per signed-in device. So
//! [`Client`] owns the provider, the signer and a map of open groups, and every
//! group operation is a method on it taking a group id. The alternative — a
//! `Group` borrowing its `Client` — is a lifetime that cannot be expressed in
//! C, and a `Group` owning its own provider is a second copy of the key store.
//!
//! ## Storage
//!
//! [`PeachyProvider`] pairs RustCrypto with [`PeachyStorage`], one
//! `StorageProvider` over a four-verb key-value backend — in memory, in
//! SQLite, or in IndexedDB across wasm-bindgen ([`crate::storage`],
//! docs/mls-core.md §Storage layout). A client opened on a store that already
//! holds groups reopens every one of them in [`Client::new`]; nothing else in
//! this file knows which backend it is on.
//!
//! Two obligations come with that, and both live here rather than in the
//! backend:
//!
//!  - **Every operation that changes state ends with a flush, on every
//!    outcome.** The backends buffer until one (`mls/core/src/storage.rs`,
//!    "Durability, and the window"), so a missed flush is an operation that
//!    never reaches the disk; and on SQLite the first write of an operation
//!    opens a transaction that holds the file's write lock until the flush
//!    commits it. So no call returns with a store transaction open, a staged
//!    commit's included (§The commit lifecycle): a write lock that outlived
//!    the call would shut every other connection to the file (a notification
//!    extension) out of writing until something unrelated flushed.
//!  - **Every operation that replaces or deletes a secret then erases it**
//!    (`KvStore::erase_superseded`): merging or processing a commit, opening
//!    or sealing an application message, taking a seat from a Welcome,
//!    forgetting a group, pruning a last-resort key package. A flush makes the
//!    new state durable; on SQLite it does not remove the old one from the
//!    write-ahead log, and a store seized after the operation would otherwise
//!    still derive what the operation was meant to leave behind
//!    (`mls/core/src/sqlite.rs` §Erasing what an operation replaced).
//!  - **Creating or joining a group records its id**, and forgetting one drops
//!    it. OpenMLS' trait has no "list the groups", so that index is ours.
//!
//! ## The commit lifecycle
//!
//! Every commit-producing method here — [`Client::add_member`],
//! [`Client::remove_member`], [`Client::replace_member`],
//! [`Client::self_update`], [`Client::refresh_credential`],
//! [`Client::set_group_meta`] — **stages** its commit and stops. It does not
//! merge. The caller owes the group exactly one of
//! [`Client::merge_pending_commit`] or [`Client::clear_pending_commit`]
//! afterwards, and which one it owes is a question only the delivery service
//! can answer:
//!
//! ```text
//!   stage  ->  submit to the delivery service  ->  accepted?  yes -> merge
//!                                                            no  -> clear,
//!                                                                   then replay
//! ```
//!
//! **Why it cannot be one call.** Peachy's delivery service is the total order
//! (docs/delivery.md §The ordering rule): it refuses a commit built
//! at any epoch but the group's current one, and that refusal is how two
//! devices committing at once are resolved. A client that merged first and
//! submitted second would, on every lost race, be sitting in an epoch the group
//! never entered — and MLS has no merge, so nothing later can reconcile it. The
//! symptom is the worst kind: the group is still `is_active`, `encrypt` still
//! returns bytes, and every one of those bytes is unreadable by every other
//! member, for ever, with nothing anywhere reporting a failure.
//!
//! **No store transaction spans the request to the delivery service.** The
//! stage is a write — OpenMLS keeps the pending commit in the group's stored
//! state, and encrypting the commit advances the handshake ratchet in the
//! store — so every stage door commits what it wrote before it returns, on
//! every outcome, a refusal included, and erases what it replaced, as a send
//! does. The verdict-dependent half stays in memory: the client holds the
//! staged commit, and the merge or the clear applies the server's answer in a
//! write of its own. On SQLite that is what keeps the file's write lock from
//! being held for the whole round trip, during which a notification extension
//! on the same file could open no message.
//!
//! **A commit saved across a restart.** A staged commit found on disk at open
//! is one whose verdict this device never heard: the process that staged it
//! died while it waited, or, on a store two processes share, it is the other
//! one's live stage. `Client::reopen_groups` keeps it and writes nothing for
//! it. The app that owns the store settles it with
//! [`Client::settle_saved_commit`] against the group's head before it
//! processes anything for the group: merged when the head is the epoch and
//! send key the commit makes, cleared when it is not, kept when the head has
//! moved past it, for its own echo through the commit door (merged: the
//! delivery service hands on only what it took) or another member's commit
//! at its epoch (which replaces it) to decide. A caller that cannot read the
//! head keeps it and asks again later. A live holder is not disturbed: its
//! merge or clear works from the stage it made, which it finds in the stored
//! group when it loads it again (§A store two processes share), and a second
//! process never settles what it did not stage.
//!
//! ## A store two processes share
//!
//! The app and its notification extension may each hold a `Client` on one
//! store. A client keeps its groups in memory between operations, and
//! OpenMLS writes a group's state back whole, so a door that acted on the
//! copy loaded before the other process wrote would put the older copy back:
//! a message key the other process spent, so a replay of that message would
//! open again, or an epoch the group has left, which nobody else can read.
//!
//! So every door that writes group state runs through `Client::synced`. It
//! takes the store's write lock before it reads anything
//! (`KvStore::begin_write`), asks whether another connection has committed
//! since the groups were loaded (`KvStore::foreign_generation`, SQLite's
//! `data_version`), loads every group again from the store when one has, and
//! only then acts. The check, the work and the write are one transaction
//! (`mls/core/src/sqlite.rs` §Another process on the file). The read doors
//! (`epoch`, `roster`, the exporters) answer from the groups as the last
//! write door left them, and the next write door catches up. A backend that
//! cannot tell another writer's commit (`foreign_generation` is `None`, as
//! for `MemoryKv`) never reloads, so one store of that kind must have one
//! live client.
//!
//! ## Wire format
//!
//! Every handshake is a `PrivateMessage`, in both directions: a commit or a
//! proposal leaves here encrypted and one that arrives in the clear is
//! refused ([`PEACHY_WIRE_FORMAT_POLICY`]). Application messages are always
//! `PrivateMessage` — that is RFC 9420, not a setting.

use std::collections::BTreeMap;

use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
use openmls::prelude::hash_ref::ProposalRef;
use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, Credential, CredentialWithKey, ExtensionType,
    GroupId, KeyPackage, KeyPackageBundle, KeyPackageRef, LeafNode, LeafNodeIndex,
    LeafNodeParameters, MlsGroup, MlsGroupCreateConfig, MlsGroupCreateConfigBuilder,
    MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, PastEpochDeletion,
    PastEpochDeletionPolicy, ProcessMessageError, ProcessedMessageContent, ProtocolVersion,
    SenderRatchetConfiguration, StagedWelcome, ValidationError, WelcomeError, WireFormatPolicy,
    PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::storage::StorageProvider as _;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;
use sha2::Digest as _;
use tls_codec::{Deserialize as _, Size as _};
use zeroize::Zeroizing;

use crate::commit_padding::{
    commit_padding_target, own_leaf_growth, welcome_bound_len, welcome_padding_target,
    welcome_trees, CommitPlan, WelcomeTrees,
};
use crate::credential::{DeviceCredential, ED25519_PUBLIC_KEY_BYTES};
use crate::error::{mls_err, CredentialRejection, Error, Result};
use crate::group_meta::{
    group_context_extensions_with_meta, group_meta_change, group_meta_extension_type,
    group_meta_from_context, unsupported_by_member,
};
use crate::identity::{
    Clock, PeachyIdentity, PeachyIdentityProvider, TrustedServerKeys, ED25519_SEED_BYTES,
};
use crate::join_request::JoinRequestVerdict;
use crate::rules::{
    DenyReason, PeachyMlsRules, PolicyDecision, ProposalContext, ProposalKind, SenderKind,
};
use crate::storage::{HeadState, PeachyProvider, PeachyStorage};

/// The delivery service's verifier-log answer for a Welcome's epoch
/// ([`Client::join_from_welcome_at_head_logged`]).
#[derive(Clone, Copy)]
struct LogAnswer<'a> {
    /// The verifier logged at the Welcome's epoch; `None` for none.
    verifier: Option<&'a [u8]>,
    /// The lowest epoch from which the log holds every epoch up to the head.
    kept_from: Option<u64>,
}

/// How a Welcome into a group this device knew was judged
/// ([`Client::judge_replacing_welcome`]): whether its signer was a device of
/// this device's own person off its approval chain, and what it changes.
struct Judged {
    untrusted: bool,
    added: Vec<String>,
    departed: Vec<String>,
    admins_changed: bool,
    /// The devices of people the Welcome keeps that it leaves out
    /// ([`RejoinReport::dropped_devices`]).
    dropped_devices: Vec<(String, String)>,
}

/// The admins a group state names (`adm`), sorted, each once; empty for no
/// state, none named, or a state that does not read.
fn admins_of(meta: Option<&[u8]>) -> Vec<String> {
    let mut admins: Vec<String> = meta
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
        .and_then(|value| value.get("adm").cloned())
        .and_then(|adm| match adm {
            serde_json::Value::Array(items) => Some(
                items
                    .into_iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .unwrap_or_default();
    admins.sort();
    admins.dedup();
    admins
}

/// How many of this device's own commits in one group the delivery service
/// may refuse in a row, with none merged between, before a copy no head has
/// matched yet is counted as CONTESTED: a server that keeps refusing them
/// keeps the copy from ever being confirmed by its own commit, and stops its
/// leaf rotation too ([`Client::clear_pending_commit`]).
const OWN_COMMITS_REFUSED_CONTEST: u32 = 16;

/// The ciphersuite Peachy ships.
///
/// `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`, code point 0x004F from
/// `draft-ietf-mls-pq-ciphersuites`: suite 1 with its HPKE KEM swapped for
/// X-Wing, the ML-KEM-768 + X25519 hybrid. Everything a group encrypts to a
/// leaf — the path secrets of every commit, the joiner's secrets in every
/// Welcome — is then protected against an adversary who records traffic now
/// and holds a quantum computer later, and still by X25519 if ML-KEM turns
/// out weaker than hoped. MLS re-runs the KEM on every commit, so the
/// protection covers every epoch, not only a group's first key.
///
/// Why this suite and no other (docs/mls-core.md §Ciphersuite 0x004F,
/// post-quantum): it is the one X-Wing suite `openmls_rust_crypto` — the
/// provider every client already links — implements
/// (`openmls_rust_crypto-0.6.0/src/provider.rs:92-107`), behind OpenMLS' own
/// `draft-ietf-mls-pq-ciphersuites` feature, with no fork or patch;
/// `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (0x004D) exists only in the
/// libcrux provider. And it keeps AES-128-GCM, SHA-256 and — the load-bearing
/// part — **Ed25519**, so the leaf signature key is still the device's Ed25519
/// public key and the credential binding in [`crate::identity`] is still a
/// byte comparison. Signatures stay classical: a forged
/// signature needs the quantum computer at the time of the attack, while a
/// recorded ciphertext can wait for one.
pub const PEACHY_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;

/// How many past epochs a group keeps decryption keys for: four, so a
/// message opens from the current epoch or any of the four before it.
///
/// Past epochs are not what carries a device that was away. Its mailbox gives
/// back commits and messages in the order the server placed them, and every
/// client drains in that order (docs/delivery.md §The ordering rule),
/// so a device that slept for a fortnight opens each message at the epoch it
/// was sealed in, however many epochs it then walks through. What a past epoch
/// is for is the one thing the server does not order: a message sealed at N
/// that is placed after the commit to N+1, because its sender sealed it before
/// it heard of that commit. Every client seals at send time, draining first,
/// and seals again on each retry, so the epochs that can land between a seal
/// and its placement are the commits other members complete during one send,
/// each needing its committer to have applied the one before.
///
/// Five readable epochs is the count a pairwise ratchet keeps of its peer's
/// sending chains, the current one included, and there is no time bound,
/// since it keeps none either. OpenMLS's time-based deletion was not used for
/// a reason of its own: it measures when an epoch BEGAN on this device, so
/// after a long quiet stretch it would drop the epoch that ended a moment ago,
/// the one an in-flight message still needs. A message that arrives later
/// than four commits is not lost: a transcript message or a lane frame is
/// asked for again by its content hint (docs/sealed-messages.md
/// §Content hints).
///
/// What the bound buys: each retained epoch is a set of keys a seized device
/// gives up for messages it has not opened yet, so a device copied today
/// yields at most the last five epochs' unread traffic, where 32 used to be
/// weeks of a busy group's. Existing groups are cut down to it when the
/// client opens (`Client::reopen_groups`). docs/mls-core.md §Group
/// configuration.
pub const RETAINED_PAST_EPOCHS: usize = 4;

/// How many past epochs' envelope secrets a copy keeps
/// ([`crate::storage`] `envelope_epochs`), beside the current one: what
/// opens a version 3 envelope sealed at an epoch the copy has left, and what
/// a reseat hands back to the device it returns a seat to
/// ([`crate::welcome_frame`] §The gap block).
///
/// More than [`RETAINED_PAST_EPOCHS`], on purpose. An envelope secret opens
/// only the envelope: the MLS message inside, from an epoch whose message
/// secrets are gone, still does not open, but its content hint and author's
/// commitment can be read ([`crate::hint`]), so the device holds a
/// placeholder and asks for the message again, as it could when every
/// envelope was keyed by the group id. A seized device gives up no message
/// it had not opened by these.
pub const ENVELOPE_PAST_EPOCHS: usize = crate::welcome_frame::WELCOME_GAP_EPOCHS - 1;

/// The most envelopes [`Client::hold_envelope`] keeps; the oldest goes
/// first.
pub const HELD_ENVELOPES_KEPT: usize = 100;

/// How long a held envelope is kept: as long as the delivery service keeps
/// one nobody acknowledged, 30 days.
pub const HELD_ENVELOPE_MAX_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// How often a client sweeps the opened messages it keeps for their envelope
/// ids ([`Client::process_message_as`]) of the old and the excess: at its
/// first keep or release, then at the first one after each hour.
pub const OPENED_PRUNE_EVERY_MS: u64 = 60 * 60 * 1000;

/// The bytes of envelopes held on device seals ([`Client::hold_envelope_sealed`])
/// past which the oldest are due to be handed out, whatever their copy's
/// epoch once it is no longer merely behind them: 16 MiB.
pub const SEALED_HELD_BUDGET_BYTES: u64 = 16 << 20;

/// The most envelopes held on device seals; one more is held without its
/// seal instead ([`HoldAnswer::Full`]).
pub const SEALED_HELD_MAX: usize = 1000;

/// The most bytes of envelopes held on device seals; one that would take the
/// hold past it is held without its seal instead: 64 MiB.
pub const SEALED_HELD_MAX_BYTES: u64 = 64 << 20;

/// What [`Client::hold_envelope_sealed`] made of an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HoldAnswer {
    /// Not kept: it opens now, is no version 3 envelope, is held already,
    /// was taken through before, or is too old. Acknowledge it.
    NotKept = 0,
    /// Kept. Acknowledge it.
    Kept = 1,
    /// The hold on device seals is at its ceiling: kept for now without its
    /// seal, as the newest of [`HELD_ENVELOPES_KEPT`]. STOP THE PAGE HERE,
    /// unacknowledged, take what [`Client::next_reopenable`] hands out
    /// through, and drain again: delivered again once that made room, it is
    /// held on its seal. Answered once until a sealed envelope is let go,
    /// so a hold that makes no room never stops the drain twice.
    Full = 2,
}

impl HoldAnswer {
    /// Whether it was kept on what came with it ([`HoldAnswer::Kept`]).
    #[must_use]
    pub const fn is_kept(self) -> bool {
        matches!(self, Self::Kept)
    }
}

/// What a held envelope handed out on its device seal is to be made of
/// ([`Client::held_disposition`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeldFate {
    /// Taken through as any envelope: opened, then read, or drawn as a
    /// placeholder and asked for again when the message inside does not
    /// open.
    Ordinary = 0,
    /// From a device of somebody who holds no leaf of the group any more: a
    /// placeholder in the group's conversation naming them, neither opened
    /// nor asked for, since nobody left in the group answers for them.
    FormerMember = 1,
    /// For a group this device holds no copy of: a placeholder in the
    /// conversation of the group the seal named, naming the sender, and
    /// asked for again once this device is seated there.
    Orphan = 2,
}

/// [`HeldFate`], with the person it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldDisposition {
    /// What it is to be made of.
    pub fate: HeldFate,
    /// The actor id of the person whose device sealed it, when it is not
    /// simply a leaf of the copy.
    pub author: Option<String>,
}

/// What a device seal beside a held envelope told this device.
enum SealRead {
    /// It opened, for a message: what to keep of it.
    Message(SealTold),
    /// It opened, for an envelope of another kind.
    NotAMessage,
    /// It opened, for a message this device opened before (a replay).
    Opened,
    /// None came, or it told nothing.
    Unread,
}

/// Who held which device key, read once per reopen pass
/// ([`Client::sealed_verdict`]): each group's own record, and the index of
/// every group's, built only if a key its own group does not know comes up.
#[derive(Default)]
struct SealPeople {
    groups: std::collections::HashMap<Vec<u8>, Option<crate::storage::LeafPeople>>,
    anywhere: Option<std::collections::HashMap<[u8; 32], String>>,
}

/// What a device seal that opened told this device.
struct SealTold {
    /// The epoch the message inside was sealed in.
    epoch: u64,
    /// The epoch envelope secret the seal carried.
    secret: Zeroizing<[u8; 32]>,
    /// The sender's device key.
    sender_key: [u8; 32],
    /// The group the seal named.
    group_id: Vec<u8>,
}

/// Whether a held envelope is handed out on its device seal now.
enum SealVerdict {
    /// Not yet: this device's copy is not past the message's epoch.
    Wait,
    /// Now, on a secret this device holds: it opens with no grant.
    Plain,
    /// Now, on the secret the seal carried: its fate, the person it names,
    /// and whether that person's device was replaced (a refusal of the
    /// message as from no member is then a loss, asked for again).
    Grant(HeldFate, Option<String>, bool),
    /// Never on its seal: it was sealed after its sender left, or handed out
    /// more than 30 days after this device saw them go.
    Drop,
    /// Not on its seal: the group's record never held its sender's key. Kept
    /// as an envelope that came with none ([`Client::demote_sealed`]).
    Unsealed,
}

/// One entry of a reopen pass ([`Client::next_reopenable`]).
enum Reopenable {
    /// Held without a seal, and opens on a secret this device holds.
    Plain(crate::storage::HeldEnvelope),
    /// Held on its seal, with the verdict that hands it out.
    Sealed(crate::storage::SealedHold, SealVerdict),
}

/// A held envelope handed out on its device seal and not yet released
/// ([`Client::next_reopenable`]), keyed by the SHA-256 of its bytes.
struct SealGrant {
    /// The mailbox id it was held under.
    id: String,
    /// The group the seal named.
    group_id: Vec<u8>,
    /// The epoch envelope secret the seal carried, on the heap: the map of
    /// grants moves its entries when it grows.
    secret: crate::storage::HeldSecret,
    /// The sender's device key.
    sender_key: [u8; 32],
    /// The SHA-256 of the MLS message inside.
    inner_digest: [u8; 32],
    /// What it is to be made of.
    fate: HeldFate,
    /// The person it names.
    author: Option<String>,
    /// Sealed by a device of a person who holds another leaf.
    by_person: bool,
}

/// The budget and the ceiling of the envelopes held on device seals.
#[derive(Debug, Clone, Copy)]
struct SealedLimits {
    budget_bytes: u64,
    max: usize,
    max_bytes: u64,
}

impl Default for SealedLimits {
    fn default() -> Self {
        Self {
            budget_bytes: SEALED_HELD_BUDGET_BYTES,
            max: SEALED_HELD_MAX,
            max_bytes: SEALED_HELD_MAX_BYTES,
        }
    }
}

/// How old this device's own leaf in a group may get before the device
/// replaces it with a fresh one: seven days.
///
/// A leaf's HPKE private key is what every commit's path secret is encrypted
/// to, so whoever copies it off a device reads every epoch of the group from
/// then on — other members' commits included, since they encrypt to it too —
/// until THIS device commits a new leaf. MLS heals only when the compromised
/// member updates (RFC 9420 §16.6). Pairwise messaging protocols heal on
/// every round trip, and rotate their prekeys every few days with a
/// fourteen-day ceiling. A leaf rotation is dearer than a DH step: it is a commit, an
/// epoch for every member, and under X-Wing about 4.7 KB in a DM and ~1.2 KB
/// per leaf in a large, freshly grown group. So the cadence is a fourteen-day
/// ceiling halved rather than a two-day rotation, and a busy device heals
/// sooner through
/// [`LEAF_ROTATION_FRAME_BUDGET`]. docs/mls-core.md §Periodic leaf rotation.
pub const LEAF_ROTATION_INTERVAL_SECONDS: i64 = 7 * 24 * 60 * 60;

/// How old this device's newest LAST-RESORT key package may get before the
/// device mints and publishes a replacement: two days.
///
/// A last-resort package is the one offer that is reused,
/// so it is the one whose init key opens many Welcomes; rotating it bounds how
/// many. docs/mls-core.md §Last-resort key packages.
pub const LAST_RESORT_ROTATION_INTERVAL_SECONDS: i64 = 2 * 24 * 60 * 60;

/// How long a REPLACED last-resort key package's private half is kept, so a
/// Welcome sealed to it before the rotation still opens: thirty days.
///
/// The rule that goes with it: never the current one; of the others, only
/// those older than this; and of those, all but the youngest.
pub const LAST_RESORT_ARCHIVE_AGE_SECONDS: i64 = 30 * 24 * 60 * 60;

/// How many frames this device may seal into a group on one leaf before it
/// rotates, however young the leaf: 250. Every application frame counts —
/// messages and the lane's marks, reactions and deletes alike — because each
/// is one more thing an attacker holding the leaf reads. Chosen so that an
/// ordinary day of chatting rotates at most once or twice, well inside what
/// [`RETAINED_PAST_EPOCHS`] lets a late reader tolerate.
pub const LEAF_ROTATION_FRAME_BUDGET: u64 = 250;

/// How young this device's own leaf in a TWO-PERSON group may be and still be
/// replaced because the other person was heard from: ten minutes.
///
/// A pairwise ratchet heals a copied device on every round trip: the first
/// thing the device sends after hearing from its peer is under a key the
/// copy does not hold. The MLS equivalent is a commit of a new leaf, so in a
/// group that seats exactly two people the leaf is also due once this device
/// has opened an application message from the other person since its leaf
/// was last put in the tree — and it rotates at the next renewal moment,
/// before its next send or in the foreground pass, so what it sends next is
/// already healed. Groups of three or more keep the seven-day and
/// frame-budget schedule above.
///
/// The floor exists because a commit is not a DH step: it is an epoch for
/// every member, a padded X-Wing commit (4.7 KB with one device each, more
/// for every further device; `commit_padding`), and one more thing
/// the drain and the notification extension apply before what follows. Ten
/// minutes is the cadence an in-call self-update already runs at, so an
/// active conversation rotates at most six times an hour per device, and a
/// compromised device is healed within ten minutes of the conversation going
/// on rather than within a week. docs/mls-core.md §Periodic leaf
/// rotation.
pub const ROUND_TRIP_ROTATION_MIN_SECONDS: i64 = 10 * 60;

/// How far BEHIND a sender's newest generation a message may still be opened,
/// per sender, per epoch.
///
/// OpenMLS's default is 5, and five is too small for Peachy. A member's
/// application ratchet carries two kinds of traffic: the messages people read,
/// and the group's own lane (sealed read and delivery marks, reactions,
/// deletes, resend answers), which a phone sends several of per message it
/// reads. A device that was away can open the lane traffic before the messages
/// it missed. By then the sender's ratchet has moved one generation per mark,
/// so with a window of five, a message sent before six marks is "too distant in
/// the past" and is gone for that device for good (`tests/out_of_order.rs`
/// replays exactly that interleaving).
///
/// A device is not guaranteed to open the two kinds in the order they were
/// sent, so "total order within an epoch" —
/// the assumption behind OpenMLS's small default — does not hold here by
/// construction, and the window has to cover the lane traffic a device can
/// miss. Equal to [`MAXIMUM_FORWARD_DISTANCE`]: anything a receiver may skip
/// over going forward, it may come back for. Each retained step is one key and
/// nonce that a device compromised inside the epoch could use to read that
/// message — the same trade [`RETAINED_PAST_EPOCHS`] makes across epochs, and
/// much smaller than it.
pub const OUT_OF_ORDER_TOLERANCE: u32 = 1000;

/// How far AHEAD of the newest generation a receiver has seen a message may
/// be. OpenMLS's default, stated so the pair is configured in one place.
pub const MAXIMUM_FORWARD_DISTANCE: u32 = 1000;

/// The sender ratchet every Peachy group reads with. See
/// [`OUT_OF_ORDER_TOLERANCE`].
fn sender_ratchet() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(OUT_OF_ORDER_TOLERANCE, MAXIMUM_FORWARD_DISTANCE)
}

/// The block every application message's encrypted content is padded to.
///
/// docs/sealed-messages.md §Size-hiding padding. Without it a sealed message's
/// ciphertext is its plaintext plus a constant, so anyone holding the row —
/// the Delivery Service included — reads off the length of what was said to
/// the byte, and "ok" versus a paragraph is not a secret.
///
/// **Where**: RFC 9420 §6.3.1's own `padding` field, through OpenMLS's
/// `padding_size`, rather than a framing of our own around `SealedPayload`.
/// The protocol already carries the zeros and every OpenMLS receiver already
/// checks they ARE zeros and strips them (ValSem011) — so a build that has
/// never heard of this constant opens a padded message unchanged, a new build
/// opens an old unpadded one unchanged, and there is no version byte, no
/// compatibility window and nothing for four clients to agree about. It
/// happens in the core, so web, iOS, Mac and Android get it from one line.
///
/// **What**: OpenMLS pads `content + signature + AEAD tag` up to a multiple
/// of this, so the ciphertext grows in whole blocks. 256 is coarser than
/// the common 80-byte block, so it hides more — every text short enough to fit
/// the first block (well past a tweet once the envelope is counted) is one
/// ciphertext length — for at most 255 bytes a message, which is noise next
/// to the transport. A fixed block rather than attachment-style
/// `1.05^n` buckets because OpenMLS offers only a fixed modulus, and because
/// message bodies are small: for a 4 KB body a 256-byte block is ~6%
/// resolution, the same order as those buckets. Attachment BLOBS are not
/// covered by this at all — they are sealed outside MLS; see the doc.
pub const APPLICATION_PADDING_BLOCK: usize = 256;

/// Handshakes are ENCRYPTED, going out and coming in, and that is what takes
/// the content of a change out of the Delivery Service's reach. It still sees the devices a
/// commit is addressed to and seats (docs/metadata.md §Encrypted
/// handshakes).
///
/// Sent as an MLS `PublicMessage` (OpenMLS'
/// `MIXED_PLAINTEXT_WIRE_FORMAT_POLICY`), every commit and every standalone
/// proposal would leave here in RFC 9420 framing, whose `FramedContent` is in
/// the CLEAR: the sender's leaf index, and — for an Add — the whole KeyPackage
/// of the person being added, credential and all. Peachy's Delivery Service
/// stores those bytes, so anybody holding its store of commits would read the
/// membership history
/// of every sealed conversation without holding a single group secret. `PrivateMessage` framing (RFC 9420 §6.3) puts the same
/// content under the epoch's sender-data and handshake keys, which no server
/// ever sees.
///
/// **Nothing on the server needed the plaintext.** `SubmitCommit` checks the
/// epoch the CLIENT names against the one it has stored, assigns the next
/// sequence and writes the bytes; it has never deserialized a handshake and it
/// keeps no ratchet tree to validate one against (the delivery service,
/// docs/metadata.md §Encrypted handshakes).
///
/// **Pure, not mixed: a plaintext handshake is REFUSED**, incoming as well
/// as outgoing. No build the server serves frames a handshake in the clear,
/// and accepting one would only let a member publish its own group's
/// membership changes to the server. The cost is written down rather than
/// hidden: a device that had not yet applied a plaintext commit when it
/// updated can never apply it now, stays at that epoch, and gets back only
/// through a fresh Welcome — see docs/delivery.md §A commit this
/// device cannot apply for when that recovery does and does not fire.
pub const PEACHY_WIRE_FORMAT_POLICY: WireFormatPolicy = PURE_CIPHERTEXT_WIRE_FORMAT_POLICY;

/// What it takes to build a [`Client`].
pub struct ClientConfig {
    /// The `pdc1` token this device was issued.
    pub credential: Vec<u8>,
    /// The device's Ed25519 private key: the raw 32-byte seed, as held in the
    /// platform key store (docs/identity.md §The key stores). It
    /// never leaves the device and it never leaves this struct — [`Client`]
    /// hands it straight to the signer, which holds it in memory only and
    /// wipes it when the client drops, and writes it to no store. It also
    /// keeps the X25519 secret derived from it, which opens device seals
    /// ([`crate::device_seal`]): that is the clamped Ed25519 signing scalar,
    /// as able to sign as the seed, so it is held in memory only and wiped
    /// when the client drops. This copy is wiped when the config drops.
    pub signature_seed: Zeroizing<[u8; ED25519_SEED_BYTES]>,
    /// Server keys from `GET /healthz/device-credential-keys`.
    pub trusted_keys: TrustedServerKeys,
    /// Group policy. [`PeachyMlsRules::default`] unless you are testing.
    pub rules: PeachyMlsRules,
    /// Optional clock override, for fixtures.
    pub clock: Option<Box<dyn Clock>>,
    /// Where this device's MLS state lives.
    ///
    /// Defaults to [`PeachyStorage::in_memory`], which is right for a test and
    /// wrong for a shipped client: a phone hands in
    /// `PeachyStorage::open(Box::new(SqliteKv::open_encrypted(path, &key)?))?`
    /// (or `SqliteKv::open_encrypted_with_plaintext_header` for a file
    /// another process opens while this one is suspended), with a random
    /// 256-bit key the platform keystore wraps, and gets its groups back
    /// after a restart; `SqliteKv::open_store` takes either key and refuses a
    /// file written in the clear. `SqliteKv::open` writes the file in the
    /// clear and exists only with the `insecure-plaintext-store` feature, for
    /// tests (`docs/mls-core.md` §Backends). The field is on the
    /// CONFIG rather than a second constructor so that a caller adding
    /// persistence changes one line and cannot accidentally get a client with
    /// neither storage nor a clock.
    pub storage: PeachyStorage,
    /// This device's own account identity key: the public key
    /// [`account_identity_public_key`](crate::account_identity_public_key)
    /// derives from the account key the device HOLDS, or `None` when it holds
    /// none (a device still waiting to be let in).
    ///
    /// The server writes `account_key` into the credential, and it can write
    /// a key it made itself. A credential certified under any key other than
    /// this one is refused as [`CredentialRejection::NotOwnAccountKey`], here
    /// and at [`Client::update_credential`]; with `None`, every certified
    /// credential is refused, since the device holds nothing to check it
    /// against. A credential with no certificate is accepted either way, as
    /// the credential of a device waiting to be let in
    /// (docs/identity.md §The account identity key).
    pub own_account_identity: Option<[u8; ED25519_PUBLIC_KEY_BYTES]>,
}

impl ClientConfig {
    pub fn new(
        credential: Vec<u8>,
        signature_seed: [u8; ED25519_SEED_BYTES],
        trusted_keys: TrustedServerKeys,
    ) -> Self {
        Self::with_seed(credential, Zeroizing::new(signature_seed), trusted_keys)
    }

    /// [`Self::new`] for a seed the caller already holds in a wiping buffer,
    /// so no plain copy of it is made on the way in.
    pub fn with_seed(
        credential: Vec<u8>,
        signature_seed: Zeroizing<[u8; ED25519_SEED_BYTES]>,
        trusted_keys: TrustedServerKeys,
    ) -> Self {
        Self {
            credential,
            signature_seed,
            trusted_keys,
            rules: PeachyMlsRules::default(),
            clock: None,
            storage: PeachyStorage::in_memory(),
            own_account_identity: None,
        }
    }

    /// Point this client at a store. Chainable, so the common line reads
    /// `ClientConfig::new(…).with_storage(PeachyStorage::open(kv)?)`.
    pub fn with_storage(mut self, storage: PeachyStorage) -> Self {
        self.storage = storage;
        self
    }

    /// Name the account identity key this device derives from the account
    /// key it holds ([`Self::own_account_identity`]). Chainable.
    pub fn with_own_account_identity(
        mut self,
        own_account_identity: Option<[u8; ED25519_PUBLIC_KEY_BYTES]>,
    ) -> Self {
        self.own_account_identity = own_account_identity;
        self
    }
}

/// One signed-in device.
pub struct Client {
    provider: PeachyProvider,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    identity: PeachyIdentity,
    /// [`ClientConfig::own_account_identity`], or the key last handed to
    /// [`Client::update_credential`].
    own_account_identity: Option<[u8; ED25519_PUBLIC_KEY_BYTES]>,
    identity_provider: PeachyIdentityProvider,
    rules: PeachyMlsRules,
    groups: BTreeMap<Vec<u8>, MlsGroup>,
    /// Group ids the store remembered and could not produce state for, dropped
    /// at open. See [`Client::reopen_groups`].
    dropped_group_ids: Vec<Vec<u8>>,
    /// Groups whose staged commit was found on disk at open: a commit some
    /// earlier run of this device staged and never heard the verdict on.
    /// Kept, not cleared, until [`Client::settle_saved_commit`] or the
    /// commit's own echo decides it (§A commit saved across a restart).
    saved_stages: std::collections::BTreeSet<Vec<u8>>,
    /// The store's [`KvStore::foreign_generation`](crate::storage::KvStore::foreign_generation)
    /// when [`Self::groups`] was last loaded from it. A write door that
    /// finds another value loads the groups again before it acts
    /// (§A store two processes share).
    store_generation: Option<u64>,
    /// How deep inside [`Client::synced`] this call is: only the outermost
    /// door takes the write lock, checks the store and closes the
    /// transaction. Put back to 0 on every way out of a door, a panic
    /// included.
    sync_depth: u32,
    /// The groups in memory may not be what the store holds: a door
    /// panicked part-way, or a reload after a rolled-back door failed. The
    /// next write door loads them again whatever the store's generation says.
    stale: bool,
    /// The live call lane's replay window, in memory (`crate::call::replay`).
    pub(crate) live_replay: crate::call::LiveReplayWindow,
    /// The last stamp this device put on a live call frame; the next is
    /// strictly greater.
    pub(crate) live_last_sent_ms: u64,
    /// The typing frames' replay window, in memory (`crate::typing`): the
    /// live lane's rule, its own record.
    pub(crate) typing_replay: crate::call::LiveReplayWindow,
    /// The last stamp this device put on a typing frame; the next is
    /// strictly greater.
    pub(crate) typing_last_sent_ms: u64,
    /// Every call's v2 participant media keys, in memory
    /// (`crate::call::media`).
    pub(crate) call_media: crate::call::media::CallMediaBook,
    /// Set by `process_inner` once a message has opened and its signature has
    /// held, and cleared before each one: whether the refusal being returned
    /// came from a device that held a leaf at the message's epoch.
    last_refusal_authenticated: bool,
    /// Per group, the last commit the commit door refused: the SHA-256 of its
    /// bytes, and whether it opened and verified before it was refused. In
    /// memory, for [`Self::commit_strands`], which a caller asks right after
    /// the refusal.
    refused_commits: BTreeMap<Vec<u8>, ([u8; 32], bool)>,
    /// The recovery driver's counts: stuck-behind readings, the fork
    /// backoff, the minute's head read and each read's snapshot
    /// ([`crate::recovery`]). In memory.
    pub(crate) recovery: crate::recovery::RecoveryBook,
    /// Per group, the sealed stamp handed in for the next commit through
    /// [`Client::note_commit_stamp`], taken by the commit door. In memory.
    pending_stamps: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Per group, what the commit door found checking the last commit's
    /// stamp ([`Client::take_commit_check`]). In memory.
    commit_checks: BTreeMap<Vec<u8>, crate::steward::CommitCheck>,
    /// Per group, the steward key the stamp of the commit going through the
    /// door right now named (`Some(None)`: it named none), opened before the
    /// merge and recorded at the epoch the merge enters
    /// ([`Client::note_copy_epoch`]), inside the merge's own write. In memory,
    /// and only for the length of one commit.
    stamp_stewards: BTreeMap<Vec<u8>, Option<[u8; 32]>>,
    /// Per group, what the commit going through a merge right now does to
    /// the steward key the group counts ([`StewardMerge`]). In memory, and
    /// only for the length of one merge.
    steward_merges: BTreeMap<Vec<u8>, StewardMerge>,
    /// The Welcome the last join refused as `AlreadyAMember`, staged and
    /// verified, until [`Client::join_contested_welcome`] settles it or the
    /// next join replaces it.
    contested_welcome: Option<StagedSeat>,
    /// The groups this device is LEAVING ([`Client::begin_leave`]), kept apart
    /// from [`Self::groups`] so that nothing but the leave reads them: no
    /// listing, no message, no send, no commit. Their state is in the store
    /// like any group's, with a leaving record beside it.
    leaving: BTreeMap<Vec<u8>, MlsGroup>,
    /// [`Client::welcome_bound_seen`].
    #[cfg(feature = "test-forgery")]
    welcome_bound_seen: Option<usize>,
    /// Whether an epoch was entered or a gap handed back since
    /// [`Client::next_reopenable`] last found nothing to open: until then a
    /// held envelope cannot have become openable, and the call answers
    /// `None` without reading them. In memory; true at every open.
    reopen_due: bool,
    /// Ids [`Client::next_reopenable`] handed out in this pass and not yet
    /// released ([`Client::release_held`]): not handed out again until the
    /// pass ends. In memory, so a process that dies before releasing one is
    /// handed it again.
    reopen_handed: std::collections::HashMap<String, Option<[u8; 32]>>,
    /// What is left of the current reopen pass, read once at its first call
    /// ([`Client::next_reopenable`]); `None` between passes, and again
    /// whenever what opens may have changed. In memory.
    reopen_queue: Option<std::collections::VecDeque<Reopenable>>,
    /// When this client last swept the hold of what a cut-short write or
    /// the 30 days left, and pruned the release notes and the records of
    /// who held each leaf: at its first reopen pass, then at the first one
    /// after each [`OPENED_PRUNE_EVERY_MS`], so a client that lives for
    /// weeks still lets them go. In memory; none at every open.
    held_swept_at_ms: Option<u64>,
    /// Whether [`Client::hold_envelope_sealed`] answered
    /// [`HoldAnswer::Full`] and no envelope held on a seal has been let go
    /// since: until one is, a full hold keeps the next without its seal and
    /// says so no more. In memory.
    hold_full_told: bool,
    /// Envelopes (by the SHA-256 of their bytes) handed out on a seal whose
    /// message was refused as not by the device the seal named
    /// ([`Client::process_message_as`]): released without being noted
    /// released, so the same bytes delivered again under their author's own
    /// seal are held again. In memory.
    seal_refused: std::collections::HashSet<[u8; 32]>,
    /// [`SEALED_HELD_BUDGET_BYTES`], [`SEALED_HELD_MAX`] and
    /// [`SEALED_HELD_MAX_BYTES`], unless a test set its own.
    sealed_limits: SealedLimits,
    /// When this client last swept the opened messages kept for their
    /// envelope ids ([`Client::process_message_as`]) of the old and the
    /// excess: at its first keep or release, then again once
    /// [`OPENED_PRUNE_EVERY_MS`] has passed, so a client that lives for
    /// weeks (a Mac app, a browser tab) still lets them go. In memory; none
    /// at every open.
    opened_swept_at_ms: Option<u64>,
    /// Held envelopes [`Client::next_reopenable`] handed out on what their
    /// device seal carried ([`crate::device_seal`]), by the SHA-256 of their
    /// bytes: [`Client::open_envelope`] opens those bytes with the secret the
    /// seal carried, and [`Client::process_message_as`] holds the message
    /// inside, by its own SHA-256, to the seal's sender. A grant lasts until
    /// [`Client::release_held`] lets the envelope go, however many are handed
    /// out before any is opened. In memory, so an envelope handed out again
    /// after a restart is granted again, after the membership check runs
    /// again.
    seal_grants: std::collections::HashMap<[u8; 32], SealGrant>,
    /// The X25519 secret that opens device seals sealed to this device and
    /// seals the ones it sends, derived once from the signature seed and
    /// wiped when the client goes. It is the clamped Ed25519 signing scalar
    /// (the birational map makes it so), as secret as the signer itself.
    device_seal_secret: zeroize::Zeroizing<[u8; 32]>,
    /// A test's stand-in for a member that hands back no gap on a reseat
    /// ([`Client::act_as_member_handing_back_no_gap`]).
    #[cfg(feature = "test-forgery")]
    hands_back_no_gap: bool,
    /// A test's stand-in for a build that seals on a leaf the tree clock
    /// calls lapsed ([`Client::act_as_build_sending_while_lapsed`]).
    #[cfg(feature = "test-forgery")]
    sends_while_lapsed: bool,
    /// Whether this device holds a group for its steward and acts on a
    /// veto: [`crate::steward::STEWARD_READS`], changed only by a test
    /// ([`Client::act_as_build_honoring_stewards`]).
    honors_stewards: bool,
    /// The own-device trust this core took from the device's main core
    /// ([`Client::adopt_own_device_trust`]): a call link's core, in memory,
    /// holds none of the main core's records otherwise. In memory; empty
    /// until adopted.
    pub(crate) adopted_own_trust: crate::own_devices::AdoptedOwnTrust,
    /// The refusals the delivery service switched on, as the app last handed
    /// them ([`Client::adopt_client_refusals`]). In memory, grown only; the
    /// app keeps them across launches and hands them in after every open.
    pub(crate) client_refusals: crate::client_refusals::ClientRefusals,
}

/// The MLS exporter label of a group's send key, whose SHA-256 is the
/// verifier on the group's head at the delivery service
/// (docs/sealed-messages.md §The anonymous door). Context: the
/// group id; length: 32.
pub const SEND_KEY_LABEL: &str = "peachy sealed-sender v1";

/// What an epoch's record lists a leaf it adds by
/// ([`crate::storage`] `envelope_epochs`): the SHA-256 of its device key.
fn device_key_digest(device_key: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(device_key).into()
}

/// One of a person's identified leaves in a tree, as [`observe_person`]
/// reads it.
#[derive(Clone, Copy)]
struct ShownLeaf {
    account_key: [u8; 32],
    issued_at: i64,
    /// [`account_leaf_digest`] of the leaf.
    leaf: [u8; 32],
}

/// Which leaf of a tree this is, for the account-key records
/// (`account_known_leaves_v2`, `account_reported_leaves_v2`): the SHA-256 of
/// `peachy account leaf v2`, then the leaf's signature key, its HPKE key and
/// its credential (TLS-encoded), each prefixed by its u64be length. The
/// credential names the person and their account key, so a leaf seated on
/// the same keys under someone else's credential, or another account key, is
/// another leaf, judged afresh: no record settled for one person can settle
/// another. The leaf's own device renewing it (an update or a new key
/// package) makes a new one, so a seat this device accepted never vouches
/// for what the device does with it later.
///
/// `None` when the credential does not encode: such a leaf has no digest,
/// and every reader skips it rather than judging it by its keys alone (the
/// version-1 digest, which a leaf under another credential could share). A
/// credential the tree decoded always encodes again, so this is never seen.
fn account_leaf_digest(member: &openmls::prelude::Member) -> Option<[u8; 32]> {
    let credential = tls_codec::Serialize::tls_serialize_detached(&member.credential).ok()?;
    let mut digest = sha2::Sha256::new();
    digest.update(ACCOUNT_LEAF_DOMAIN);
    for field in [
        member.signature_key.as_slice(),
        member.encryption_key.as_slice(),
        credential.as_slice(),
    ] {
        digest.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(field);
    }
    Some(digest.finalize().into())
}

/// The label of [`account_leaf_digest`].
pub(crate) const ACCOUNT_LEAF_DOMAIN: &[u8] = b"peachy account leaf v2";

/// The label the version-1 leaf records were kept under
/// ([`account_leaf_digest_v1`]).
pub(crate) const ACCOUNT_LEAF_V1_DOMAIN: &[u8] = b"peachy account leaf v1";

/// The digest the version-1 leaf records were kept by: the signature key
/// and the HPKE key alone. Read only to carry those records over
/// (`Client::carry_leaf_records_v1`); a record of a leaf the tree no longer
/// holds is dropped then, as every read drops it.
fn account_leaf_digest_v1(member: &openmls::prelude::Member) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    digest.update(ACCOUNT_LEAF_V1_DOMAIN);
    digest.update(
        u64::try_from(member.signature_key.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(&member.signature_key);
    digest.update(&member.encryption_key);
    digest.finalize().into()
}

/// The newest of `leaves` by signed `iat`; of equal ones, the lowest account
/// key, so every reading of one tree picks the same leaf.
fn newest_leaf<'a>(leaves: impl Iterator<Item = &'a ShownLeaf>) -> Option<&'a ShownLeaf> {
    leaves.max_by(|a, b| {
        a.issued_at
            .cmp(&b.issued_at)
            .then_with(|| b.account_key.cmp(&a.account_key))
    })
}

/// The newest of `leaves` whose `iat` is at most
/// [`ACCOUNT_KEY_FUTURE_SKEW_SECONDS`] past `now`, when any is; else the
/// newest of them all. A first sight and a pin with no time recorded are
/// dated by it, so a leaf dated months ahead never outranks the person's real ones.
fn newest_believable<'a>(
    leaves: impl Iterator<Item = &'a ShownLeaf> + Clone,
    now: i64,
) -> Option<&'a ShownLeaf> {
    let bound = now.saturating_add(ACCOUNT_KEY_FUTURE_SKEW_SECONDS);
    newest_leaf(leaves.clone().filter(|l| l.issued_at <= bound)).or_else(|| newest_leaf(leaves))
}

/// How far past this device's clock a leaf's `iat` may be and still move a
/// person's pin ([`observe_person`]). The issuer floors `iat` to the UTC
/// day, so an honest one is never ahead; a day covers a device clock that
/// is behind. A leaf past it is reported, never pinned: an `iat` months
/// ahead would otherwise outrank every real device of the person.
pub const ACCOUNT_KEY_FUTURE_SKEW_SECONDS: i64 = 24 * 60 * 60;

/// The latest `iat` among `leaves` under `key`, never past `now`: what the
/// pin is dated by.
fn latest_under(leaves: &[ShownLeaf], key: &[u8; 32], now: i64) -> Option<i64> {
    leaves
        .iter()
        .filter(|l| l.account_key == *key)
        .map(|l| l.issued_at)
        .max()
        .map(|latest| latest.min(now))
}

/// What [`observe_person`] reads of one conversation besides its tree.
struct ConversationLeaves<'a> {
    /// The leaves this conversation settled while their key was the
    /// person's current one. Grows as it reads. A leaf here whose key the
    /// person has since moved away from is NOT settled: the conversation
    /// still encrypts to it, and says so once, which moves it to `reported`
    /// ([`Client::observe_account_keys`] keeps no leaf in both).
    known: &'a mut Vec<[u8; 32]>,
    /// The leaves this conversation reported, or accepted in silence at a
    /// first sight, under a key not the person's current one. Settled while
    /// that key is not current: a rejoin or a later read says nothing of
    /// them. Grows as it reads; each read drops the leaves under the key
    /// current then, which `known` holds, and a pin moved in another
    /// conversation drops those under a key it moved to or off here, this
    /// copy held or forgotten for a rejoin
    /// (`Client::settle_reports_on_pin_move`), so the report of a leaf
    /// whose key came and went while this one was not read silences nothing.
    reported: &'a mut Vec<[u8; 32]>,
    /// No record of `known` yet: a conversation with `account_seen` and no
    /// `known` record, or one read for the first time.
    legacy: bool,
}

/// [`Client::observe_account_keys`] for one person of `group_id`, whose
/// identified leaves there are `leaves`: whether this conversation reports
/// their security code changing.
fn observe_person(
    storage: &PeachyStorage,
    group_id: &[u8],
    actor_id: &str,
    leaves: &[ShownLeaf],
    conversation: ConversationLeaves<'_>,
    now: i64,
) -> Result<bool> {
    let ConversationLeaves {
        known,
        reported,
        legacy,
    } = conversation;
    // The newest leaf whose `iat` this device's clock believes: a first
    // sight never pins a key on a leaf dated far ahead of every real one.
    let Some(newest) = newest_believable(leaves.iter(), now) else {
        return Ok(false);
    };
    let stored_pins = storage.account_pins(actor_id)?;
    let stored_retired = storage.account_retired(actor_id)?;
    let stored_since = storage.account_pin_since(actor_id)?;
    let seen = storage.account_seen(group_id, actor_id)?;
    let mut pinned = stored_pins.clone();
    let mut retired = stored_retired.clone();
    let mut since = stored_since;
    let mut report = false;

    if pinned.is_empty() && retired.is_empty() {
        // First sight: every key this tree shows is accepted, the newest
        // leaf's as current, in silence.
        let key = newest.account_key;
        pinned = vec![key];
        retired.extend(leaves.iter().map(|l| l.account_key).filter(|k| *k != key));
        since = latest_under(leaves, &key, now);
        known.extend(
            leaves
                .iter()
                .filter(|l| l.account_key == key)
                .map(|l| l.leaf),
        );
        reported.extend(
            leaves
                .iter()
                .filter(|l| l.account_key != key)
                .map(|l| l.leaf),
        );
    } else {
        // A conversation with `account_seen` and no `known` record: the keys
        // it showed there were accepted there (only one of a tree's keys was
        // pinned). One never retired may be the current one; a retired one
        // never is.
        let legacy_accepted: Vec<[u8; 32]> = if legacy {
            seen.iter()
                .filter(|k| !retired.contains(k))
                .copied()
                .collect()
        } else {
            Vec::new()
        };
        if since.is_none() {
            // A pin with no record of when it became current: read that off
            // this tree's leaves under the PINNED key (or a key accepted in
            // this conversation), and
            // nothing else. With none here, it stays unknown and nothing
            // moves.
            if let Some(leaf) = newest_believable(
                leaves.iter().filter(|l| {
                    pinned.contains(&l.account_key) || legacy_accepted.contains(&l.account_key)
                }),
                now,
            ) {
                let key = leaf.account_key;
                retired.extend(
                    pinned
                        .iter()
                        .chain(legacy_accepted.iter())
                        .copied()
                        .filter(|k| *k != key),
                );
                pinned = vec![key];
                since = latest_under(leaves, &key, now);
            }
        }
        if legacy {
            // A conversation with no `known` record: the keys it showed there
            // were accepted there. They are accepted, never made current,
            // and their leaves here are settled.
            for key in &seen {
                if !pinned.contains(key) && !retired.contains(key) {
                    retired.push(*key);
                }
            }
            for leaf in leaves.iter().filter(|l| seen.contains(&l.account_key)) {
                if pinned.contains(&leaf.account_key) {
                    known.push(leaf.leaf);
                } else {
                    reported.push(leaf.leaf);
                }
            }
        }
        // The person's leaves under their current key are theirs here.
        known.extend(
            leaves
                .iter()
                .filter(|l| pinned.contains(&l.account_key))
                .map(|l| l.leaf),
        );

        // Every other leaf not yet settled here is a change: a key never
        // accepted, or one they moved away from. A leftover of a replaced
        // device is no exception: whoever composed the tree chose it, and the
        // conversation encrypts to it. Nor is a leaf this conversation settled
        // while its key was current: once the person moved off that key, the
        // conversation still encrypts to it, and says so once.
        let mut moved_to: Option<&ShownLeaf> = None;
        let mut never_accepted = false;
        let mut came_back = false;
        let mut left_behind = false;
        for leaf in leaves {
            if pinned.contains(&leaf.account_key) || reported.contains(&leaf.leaf) {
                continue;
            }
            let accepted = retired.contains(&leaf.account_key);
            let settled_before = known.contains(&leaf.leaf);
            reported.push(leaf.leaf);
            report = true;
            if settled_before {
                left_behind = true;
            } else if accepted {
                came_back = true;
            } else {
                never_accepted = true;
                retired.push(leaf.account_key);
            }
            // The pin moves only to a leaf issued after the one that made the
            // current key current; an older one is reported and accepted,
            // and the live key stays. With no such time (a pin with no
            // time recorded, none of whose leaves is here) the reported leaf moves it:
            // never in silence. The issuer floors `iat` to the day, so a key
            // never accepted, issued the same day, is taken as the later
            // one; a key they moved away from must be strictly later. An
            // `iat` past this device's clock moves nothing.
            let believable = leaf.issued_at <= now.saturating_add(ACCOUNT_KEY_FUTURE_SKEW_SECONDS);
            let later = believable
                && since.is_none_or(|since| {
                    if accepted {
                        leaf.issued_at > since
                    } else {
                        leaf.issued_at >= since
                    }
                });
            if later && moved_to.is_none_or(|m| leaf.issued_at > m.issued_at) {
                moved_to = Some(leaf);
            }
        }
        if never_accepted {
            log::info!(
                "peachy-mls: a conversation shows a person under an account key this device \
                 never accepted for them; their security code changed"
            );
        }
        if came_back {
            log::info!(
                "peachy-mls: a conversation shows a person under an account key they had moved \
                 away from, on a leaf it did not hold; their security code changed"
            );
        }
        if left_behind {
            log::info!(
                "peachy-mls: a conversation still shows a person under an account key they moved \
                 away from elsewhere; their security code changed"
            );
        }
        if let Some(leaf) = moved_to {
            let key = leaf.account_key;
            retired.extend(pinned.iter().copied());
            retired.retain(|k| *k != key);
            pinned = vec![key];
            since = latest_under(leaves, &key, now);
            known.extend(
                leaves
                    .iter()
                    .filter(|l| l.account_key == key)
                    .map(|l| l.leaf),
            );
        }
        // A report here covers every leaf of theirs this tree shows under a
        // key not current now, the old key's settled leaves included when the
        // pin moved in this very read: one notice per conversation.
        if report {
            reported.extend(
                leaves
                    .iter()
                    .filter(|l| !pinned.contains(&l.account_key))
                    .map(|l| l.leaf),
            );
        }
    }

    // A report settles a leaf only while its key is not current. One under
    // the key current after this read is settled in `known` (every branch
    // above put it there), whatever reported it before, so the conversation
    // names it once if the person moves off that key: it still encrypts to it.
    reported.retain(|digest| {
        !leaves
            .iter()
            .any(|l| l.leaf == *digest && pinned.contains(&l.account_key))
    });

    retired.retain(|k| !pinned.contains(k));
    retired.sort_unstable();
    retired.dedup();
    if pinned != stored_pins {
        storage.set_account_pins(actor_id, &pinned)?;
    }
    if retired != stored_retired {
        storage.set_account_retired(actor_id, &retired)?;
    }
    if since != stored_since {
        if let Some(since) = since {
            storage.set_account_pin_since(actor_id, since)?;
        }
    }

    // Once per conversation: a report there, or the first current key it
    // shows after showing the person only under another, says so there.
    // Only a current key is ever recorded as what a conversation showed.
    let mut catches_up = false;
    let here: Vec<[u8; 32]> = leaves
        .iter()
        .map(|l| l.account_key)
        .filter(|k| pinned.contains(k))
        .collect();
    if report {
        storage.set_account_seen(group_id, actor_id, &pinned)?;
    } else if !here.is_empty() && !seen.iter().any(|k| pinned.contains(k)) {
        catches_up = !seen.is_empty();
        storage.set_account_seen(group_id, actor_id, &here)?;
    }
    if catches_up {
        log::info!(
            "peachy-mls: a conversation now shows a person under the account key another \
             conversation already showed them move to"
        );
    }
    Ok(report || catches_up)
}

/// What the commit door reads off a copy before a commit merges, to check
/// the commit's sealed stamp after (`Client::check_stamp`).
struct StampInputs {
    /// The epoch the commit was built in.
    epoch: u64,
    /// That epoch's send key ([`SEND_KEY_LABEL`]).
    send_key: Zeroizing<Vec<u8>>,
    /// That epoch's commit MAC key ([`crate::steward::COMMIT_MAC_LABEL`]).
    mac_key: Zeroizing<Vec<u8>>,
    /// The steward key the meta named at that epoch.
    steward: Option<[u8; 32]>,
}

/// What the commit going through a merge right now does to the steward key
/// the group COUNTS for enrollment (`Client::enrolled_steward_key`): read off
/// the copy before the merge, settled at the epoch the merge enters
/// (`Client::note_copy_epoch`), inside the merge's own write.
struct StewardMerge {
    /// The meta's own `stw.k` before the merge.
    named_before: Option<[u8; 32]>,
    /// The key the group counted before the merge.
    counted_before: Option<[u8; 32]>,
    /// Whether the committer may change the counted key
    /// (`crate::steward::may_change_steward_key`).
    may_change: bool,
    /// This device's own commit. The server took it, and with it the steward
    /// change it carried, so a new `stw.k` it wrote is the handle's key: the
    /// founder and a rotator record it as stamped themselves, since no stamp
    /// comes back to the committing device.
    own: bool,
}

/// A Welcome staged and verified, not yet kept.
struct StagedSeat {
    group_id: Vec<u8>,
    staged: StagedWelcome,
    sealed_to: Vec<Vec<u8>>,
    welcome_sender: Option<String>,
    /// The account key the Welcome's signer's credential carries, beside its
    /// actor: what [`Client::judge_replacing_welcome`] matches against the
    /// roster this device knew.
    welcome_sender_key: Option<[u8; 32]>,
    /// The Welcome signer's device id and device key: what
    /// [`Client::judge_replacing_welcome`] holds a signer of this device's
    /// own person to, since its account key proves nothing about which of
    /// the person's devices, live or removed, signed.
    welcome_sender_device: Option<(String, [u8; 32])>,
    /// What a seat taken through a last-resort package is remembered by, so
    /// it is never taken twice: [`crate::storage::welcome_taken_key`] of the
    /// group, epoch and transcript its verified GroupInfo names.
    taken_key: Vec<u8>,
    /// The sealed gap block a reseat's version 2 frame carried
    /// ([`crate::welcome_frame`] §The gap block).
    gap_block: Option<Vec<u8>>,
}

/// One person in a roster this device remembers: the actor, and the account
/// identity key their leaves carried. Matched on both, because the delivery
/// service issues device credentials and could name any actor in one; only
/// that person's own devices can sign under their account key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct RosterClaim {
    #[serde(rename = "a")]
    pub(crate) actor_id: String,
    /// The 32-byte account key; absent for a leaf that carried none.
    #[serde(rename = "k", default, skip_serializing_if = "Option::is_none")]
    pub(crate) account_key: Option<[u8; 32]>,
}

impl RosterClaim {
    /// Whether `person` (an actor and the account key a leaf carries) is
    /// the person this entry names: the same actor, under the same key, or
    /// under any key when this entry kept none.
    pub(crate) fn is_matched_by(&self, person: &RosterClaim) -> bool {
        self.actor_id == person.actor_id
            && match (self.account_key, person.account_key) {
                (Some(kept), Some(now)) => kept == now,
                (None, _) => true,
                (Some(_), None) => false,
            }
    }
}

/// What a Welcome brought with it when it restored or replaced a copy of a
/// group this device already knew ([`Client::take_rejoin_report`]): who
/// re-added this device, who is in the group now that was not in the roster
/// it last saw, who of that roster is not, and whether the admins changed.
/// The client draws all of it in the transcript, so a person is never moved
/// into a different group, or into a group with other people in it, without
/// being told. One report per Welcome, kept in order until the client says it
/// drew it ([`Client::peek_rejoin_report`], [`Client::drop_rejoin_report`]),
/// so a later Welcome never hides an earlier one and a process that dies
/// mid-draw draws it again.
///
/// Also kept for a copy the delivery service contradicted
/// ([`Self::contested`]), with no re-add at all ([`Self::readded_by`]
/// empty).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RejoinReport {
    /// The actor whose commit seated this device again (the Welcome's signer).
    /// Empty in a report of a contested copy alone ([`Self::contested`]).
    #[serde(rename = "by")]
    pub readded_by: String,
    /// The device of [`Self::readded_by`] whose commit it was. Empty in a
    /// report kept by a build before this was.
    #[serde(rename = "d", default, skip_serializing_if = "String::is_empty")]
    pub readded_by_device: String,
    /// Whether the Welcome's signer claims this device's own person but is
    /// not a device this device trusts as one of its own: not on its
    /// approval chain, or under another account key. This is what tells
    /// "one of my devices" from a device the person never let in. Anybody
    /// else is drawn by name. A device the account forgot never gets this
    /// far: its Welcome is refused. False in a report kept by a build before
    /// this was.
    #[serde(rename = "u", default, skip_serializing_if = "std::ops::Not::not")]
    pub readded_by_untrusted: bool,
    /// The actors in the new tree who were not in the roster this device last
    /// saw, sorted, this device's own person never among them. A person is
    /// matched by actor and account key, so an actor of that roster back
    /// under another account key is here, and in [`Self::departed_actors`]
    /// too.
    #[serde(rename = "added", default)]
    pub added_actors: Vec<String>,
    /// The actors of the roster this device last saw whom the new tree
    /// leaves out (by actor and account key), sorted, this device's own
    /// person never among them. Nobody this device already saw leave from a
    /// roster it kept when it forgot the group is named again; anybody
    /// seated in the copy being replaced always is. Always drawn ("{name} is
    /// no longer in this chat"). Empty in a report kept by a build before
    /// this was.
    #[serde(rename = "left", default, skip_serializing_if = "Vec::is_empty")]
    pub departed_actors: Vec<String>,
    /// Whether the new tree's admins (`adm`) are not the ones of the group
    /// state this device last saw there. Always drawn.
    #[serde(rename = "adm", default, skip_serializing_if = "std::ops::Not::not")]
    pub admins_changed: bool,
    /// Whether the delivery service contradicted the copy this device held
    /// while no head had matched it yet (docs/delivery.md §Two seats
    /// under one group id): a head naming one of its epochs under another
    /// send key, or the head given at its join not matching it once it got
    /// there. Drawn so the person is told before any Welcome replaces it.
    #[serde(rename = "c", default, skip_serializing_if = "std::ops::Not::not")]
    pub contested: bool,
    /// The devices, as (actor, device id), that the copy or roster this
    /// device last saw held for a person the new tree still holds, and that
    /// the new tree leaves out, sorted; never this device itself, nor a
    /// device this account forgot. A member who keeps a person through one
    /// of their devices and leaves another out of a group of their own shows
    /// here, though no person changed. The client re-seats its own person's
    /// devices at once; another person's are logged, never drawn (a person's
    /// devices draw no line). Empty in a report kept by a build before this
    /// was.
    #[serde(rename = "dd", default, skip_serializing_if = "Vec::is_empty")]
    pub dropped_devices: Vec<(String, String)>,
    /// What the report is dropped by once drawn ([`Client::drop_rejoin_report`]):
    /// random and nonzero, set when it is kept. 0 in a report kept by a
    /// build before this was, until the first peek gives it one.
    #[serde(rename = "n", default, skip_serializing_if = "is_zero")]
    pub id: u64,
    /// When the client first drew it, in Unix milliseconds, as the first
    /// [`Client::peek_rejoin_report`] was told: 0 until then. Every later
    /// peek answers the same time, so a client that draws its lines at this
    /// time and keys them by it writes the same lines again after a crash,
    /// never a second set.
    #[serde(rename = "t", default, skip_serializing_if = "is_zero")]
    pub drawn_at_ms: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// A random nonzero report id ([`RejoinReport::id`]).
fn fresh_report_id() -> Result<u64> {
    loop {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes)
            .map_err(|err| Error::Mls(format!("no randomness for a report id: {err}")))?;
        let id = u64::from_be_bytes(bytes);
        if id != 0 {
            return Ok(id);
        }
    }
}

/// How many rejoin reports a group keeps for the client to take
/// ([`Client::take_rejoin_report`]); past it, a new one is folded into the
/// newest ([`RejoinReport::fold`]).
pub const REJOIN_REPORTS_KEPT: usize = 32;

impl RejoinReport {
    /// How many milliseconds the report owns from [`Self::drawn_at_ms`]: one
    /// more than the lines a client can draw for it (a contested line, a
    /// re-add line, an admins line, one per person added and one per person
    /// gone), so the next report of the group is drawn after all of them.
    pub fn line_span(&self) -> u64 {
        4 + self.added_actors.len() as u64 + self.departed_actors.len() as u64
    }

    /// Fold `next` into this report: every flag either set, and everybody
    /// either names as added or gone, are kept; the re-adder is `next`'s
    /// unless only this one's is untrusted, so the other re-add line is lost
    /// and an untrusted re-adder is always the one named.
    fn fold(&mut self, next: RejoinReport) {
        let keep_ours = self.readded_by_untrusted && !next.readded_by_untrusted;
        if !next.readded_by.is_empty() && !keep_ours {
            self.readded_by = next.readded_by;
            self.readded_by_device = next.readded_by_device;
        }
        self.readded_by_untrusted |= next.readded_by_untrusted;
        self.admins_changed |= next.admins_changed;
        self.contested |= next.contested;
        for (into, from) in [
            (&mut self.added_actors, next.added_actors),
            (&mut self.departed_actors, next.departed_actors),
        ] {
            into.extend(from);
            into.sort();
            into.dedup();
        }
        self.dropped_devices.extend(next.dropped_devices);
        self.dropped_devices.sort();
        self.dropped_devices.dedup();
    }
}

/// Translate the one commit-build failure a rename has a SENTENCE for.
///
/// OpenMLS refuses a `GroupContextExtensions` commit whose new required
/// capabilities name an extension some member's leaf does not advertise, and
/// refuses it again if the committer's own updated leaf does not. Both are the
/// same fact — somebody in this group is on a leaf that predates
/// `peachy_group_meta` — and both have the same
/// remedy: that member's next leaf renewal advertises it
/// ([`Client::credential_refresh_due`]). Everything else stays an [`Error::Mls`] string, because
/// inventing a friendly sentence for a failure nobody has diagnosed is how a
/// wrapper starts lying about which case it is in.
fn group_context_build_error(err: openmls::prelude::CreateCommitError) -> Error {
    use openmls::prelude::{
        CreateCommitError, GroupContextExtensionsProposalValidationError as GceError,
    };
    use openmls::treesync::errors::LeafNodeValidationError;
    match &err {
        CreateCommitError::GroupContextExtensionsProposalValidationError(
            GceError::RequiredExtensionNotSupportedByAllMembers
            | GceError::ExtensionNotSupportedByAllMembers,
        )
        | CreateCommitError::LeafNodeValidation(LeafNodeValidationError::UnsupportedExtensions) => {
            unsupported_by_member(&err.to_string())
        }
        _ => mls_err(err),
    }
}

/// The GroupContext extension types every Peachy leaf must advertise.
///
/// RFC 9420 §12.1.6 and OpenMLS' `validate_group_context_extensions_proposal`:
/// a `GroupContextExtensions` proposal carrying a non-default extension type
/// is refused unless EVERY member's leaf advertises it — so these go on every
/// leaf this build makes, whether or not its group ever uses them.
/// `crate::group_meta` §Capabilities is the long form.
const PEACHY_GROUP_CONTEXT_TYPES: [u16; 1] = [crate::group_meta::PEACHY_GROUP_META_EXTENSION_TYPE];

/// The capability every leaf advertises to say its device reads version 3
/// envelopes, the ones keyed by the epoch
/// ([`crate::envelope::ENVELOPE_VERSION_EPOCH`]). `0xF1AA`, in RFC 9420's
/// private-use range, beside `peachy_group_meta`'s `0xF1A9`. It names no
/// extension a group or a package ever carries, and no receiver checks it.
/// Not in [`PEACHY_GROUP_CONTEXT_TYPES`]: a leaf without it blocks nothing.
pub const PEACHY_READS_EPOCH_ENVELOPES: u16 = 0xF1AA;

fn reads_epoch_envelopes_type() -> ExtensionType {
    ExtensionType::Unknown(PEACHY_READS_EPOCH_ENVELOPES)
}

/// The capabilities every Peachy leaf advertises: the defaults, the one
/// ciphersuite this build speaks, [`PEACHY_GROUP_CONTEXT_TYPES`] and
/// [`PEACHY_READS_EPOCH_ENVELOPES`].
///
/// `ciphersuites` is pinned to [`PEACHY_CIPHERSUITE`] rather than left to
/// OpenMLS' default list, because that is the only suite this build speaks
/// (docs/mls-core.md §Ciphersuite 0x004F, post-quantum). The `proposals`
/// list stays empty on purpose: `GroupContextExtensions` is a DEFAULT proposal
/// type in RFC 9420 §17.4.
fn peachy_leaf_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[PEACHY_CIPHERSUITE]),
        Some(&[group_meta_extension_type(), reads_epoch_envelopes_type()]),
        None,
        None,
    )
}

/// `config` with only its `padding_size` changed. OpenMLS keeps the other
/// fields crate-private and offers no way to read them all back, so the copy
/// goes through the config's own serde form, which carries every field.
fn join_config_with_padding(
    config: &MlsGroupJoinConfig,
    padding: usize,
) -> Result<MlsGroupJoinConfig> {
    let mut value = serde_json::to_value(config)
        .map_err(|err| Error::Mls(format!("could not read the group config: {err}")))?;
    let Some(fields) = value.as_object_mut() else {
        return Err(Error::Mls("the group config is not a record".into()));
    };
    if !fields.contains_key("padding_size") {
        return Err(Error::Mls("the group config carries no padding".into()));
    }
    fields.insert("padding_size".into(), padding.into());
    serde_json::from_value(value)
        .map_err(|err| Error::Mls(format!("could not write the group config: {err}")))
}

/// [`peachy_leaf_capabilities`] plus `last_resort`, for a last-resort key
/// package's leaf only.
///
/// RFC 9420 §10.1 (OpenMLS: `KeyPackageIn::validate`): every extension in a
/// KeyPackage's `extensions` must also be listed in its leaf's
/// `capabilities.extensions`, so a package marked last-resort whose leaf does
/// not say so is refused by every adder.
fn peachy_last_resort_leaf_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[PEACHY_CIPHERSUITE]),
        Some(&[
            group_meta_extension_type(),
            reads_epoch_envelopes_type(),
            ExtensionType::LastResort,
        ]),
        None,
        None,
    )
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No signer, no provider: one holds the device private key and the
        // other holds every group secret. A Debug that prints them is a Debug
        // that puts them in a log.
        f.debug_struct("Client")
            .field("actor_id", &self.identity.actor_id)
            .field("device_id", &self.identity.device_id)
            .field("groups", &self.groups.len())
            .finish()
    }
}

/// What came out of a commit-producing operation.
///
/// **The commit in here is STAGED, not merged.** See §The commit lifecycle on
/// [`Client`]: the caller owes this group either
/// [`Client::merge_pending_commit`] or [`Client::clear_pending_commit`] before
/// it can build another one.
#[derive(Debug, Clone)]
pub struct CommitBundle {
    /// The commit, for every other member. Serialized `MLSMessage`.
    pub commit: Vec<u8>,
    /// The Welcome, present only when the commit added somebody.
    pub welcome: Option<Vec<u8>>,
    /// The epoch this commit PRODUCES — the group's epoch once it is merged,
    /// which is one past the epoch it was built at (RFC 9420 §8.1: a commit
    /// increments `GroupContext.epoch` by exactly one).
    ///
    /// Note that this is NOT the number the delivery service checks. Its
    /// ordering rule is against the epoch the commit was built AT
    /// (docs/delivery.md §The ordering rule), which is what
    /// [`Client::epoch`] answers while the commit is still staged.
    pub epoch: u64,
}

/// What a commit did to the group, once processed.
#[derive(Debug, Clone)]
pub struct CommitOutcome {
    pub sender: PeachyIdentity,
    /// Identities added by this commit, already validated.
    pub added: Vec<PeachyIdentity>,
    /// Leaf indices removed by this commit.
    pub removed: Vec<u32>,
    /// Whether this commit removed *us*. After this the group is no longer
    /// active and [`Client::encrypt`] will refuse.
    pub removed_self: bool,
    /// The people who LEFT in this commit: each proposed the removal of
    /// every leaf of theirs (a leave, [`Client::propose_leave`]) and this
    /// commit took them all out by those proposals. Sorted. This device's
    /// own person is among them when one of its devices left. What a client
    /// draws "{name} left" from; a person removed by somebody else is never
    /// here.
    pub left: Vec<String>,
    pub epoch: u64,
}

/// The result of feeding one incoming message to [`Client::process_message`]
/// or [`Client::process_commit`]. `Debug` gives an application message's
/// length, not its words.
#[derive(Clone)]
pub enum Incoming {
    /// An application message, decrypted.
    Application {
        sender: PeachyIdentity,
        plaintext: Vec<u8>,
    },
    /// A proposal, policy-checked and queued for the next commit.
    ProposalQueued {
        sender: PeachyIdentity,
        kind: ProposalKind,
    },
    /// A commit, policy-checked and merged.
    Commit(CommitOutcome),
    /// A message this client sent, handed back by the delivery service. The
    /// own sender ratchet is encryption-only, so there is nothing to read and
    /// nothing to do; a caller shows the copy it already has.
    Echo,
}

impl Incoming {
    /// Wipe an application message's words: the core's own copy of a
    /// message it refuses after it opened, before the copy drops.
    fn wipe_words(&mut self) {
        if let Self::Application { plaintext, .. } = self {
            zeroize::Zeroize::zeroize(plaintext);
        }
    }
}

impl std::fmt::Debug for Incoming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Application { sender, plaintext } => f
                .debug_struct("Application")
                .field("sender", sender)
                .field("plaintext_len", &plaintext.len())
                .finish(),
            Self::ProposalQueued { sender, kind } => f
                .debug_struct("ProposalQueued")
                .field("sender", sender)
                .field("kind", kind)
                .finish(),
            Self::Commit(outcome) => f.debug_tuple("Commit").field(outcome).finish(),
            Self::Echo => f.write_str("Echo"),
        }
    }
}

/// What [`Client::settle_saved_commit`] did with a commit found staged at
/// open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedCommit {
    /// The head was the commit's: merged.
    Merged,
    /// The head was not the commit's: cleared.
    Cleared,
    /// The head is past the commit's epoch: kept for its echo, or another
    /// member's commit at its epoch, to decide.
    Waiting,
}

/// What [`Client::founding_checks`] answers: the packages that passed, in
/// order, each with its index and device id, and each refused one's index
/// with the reason.
type FoundingSort = (Vec<(u32, String, KeyPackage)>, Vec<(u32, Error)>);

/// One epoch's envelope secret: the epoch and its 32 bytes.
type EpochSecret = (u64, [u8; 32]);

/// A roster entry.
#[derive(Debug, Clone)]
pub struct RosterEntry {
    pub leaf_index: u32,
    /// `Ok` when the leaf's credential checks out; `Err` names why it does not.
    ///
    /// Deliberately not a filtered list of valid members. A leaf whose
    /// credential has expired is still IN the tree and still receives every
    /// message; hiding it from the roster would show the person a group that
    /// does not match who can read it.
    pub identity: std::result::Result<PeachyIdentity, CredentialRejection>,
    /// The leaf's tree signature key, raw bytes, for every leaf, verified or
    /// not. What [`Client::remove_member`] takes beside the index, so a
    /// removal names the leaf this entry described and not whoever sits at
    /// its index by the time the removal runs.
    pub leaf_key: Vec<u8>,
}

impl Client {
    /// Build a client, validating its own credential on the way in, and reopen
    /// every group its store already holds.
    ///
    /// The self-check is the point: a device that cannot prove its own leaf is
    /// a device whose first Add proposal every peer will refuse, and finding
    /// that out here — with a named reason — beats finding it out as a remote
    /// rejection later.
    ///
    /// The reopen is the other half. On an in-memory store there is nothing to
    /// reopen and this costs one scan of an empty namespace; on a SQLite or
    /// IndexedDB store it is what makes `new` mean "open", and it is eager
    /// rather than lazy because a group that fails to load should say so at
    /// sign-in, not at the moment somebody tries to read a message in it.
    pub fn new(config: ClientConfig) -> Result<Self> {
        let ClientConfig {
            credential,
            signature_seed,
            trusted_keys,
            rules,
            clock,
            storage,
            own_account_identity,
        } = config;

        let signing = ed25519_dalek::SigningKey::from_bytes(&signature_seed);
        let public = signing.verifying_key().to_bytes();

        let identity_provider = match clock {
            Some(clock) => PeachyIdentityProvider::with_clock(trusted_keys, clock),
            None => PeachyIdentityProvider::new(trusted_keys),
        };
        let identity = identity_provider.validate_token(&credential, &public)?;
        crate::identity::check_own_account_key(&identity, own_account_identity.as_ref())?;

        // Parsed once more only to fail early on a token that validated but
        // whose device_key somehow is not the key we hold. `validate_token`
        // already compares them, so this is belt and braces around the single
        // most consequential equality in the crate.
        let parsed = DeviceCredential::parse(&credential)?;
        if parsed.device_key() != &public {
            return Err(CredentialRejection::LeafKeyMismatch.into());
        }

        let provider = PeachyProvider::new(storage);
        let device_seal_secret = crate::device_seal::device_seal_secret(&signature_seed);
        let signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            signature_seed.to_vec(),
            public.to_vec(),
        );
        // The signer lives in memory only, built above from the seed the
        // platform key store hands in at every open; OpenMLS takes it as an
        // argument and never looks one up in the store, so the store keeps
        // no copy of the private key (`storage.rs` refuses the write).
        //
        // Builds before this one wrote the key pair into the store. Erased
        // here, once: a store that holds none answers a scan and nothing is
        // written, so an open of an existing store stays reads only (a write
        // opens the deferred transaction a flush commits, and iOS kills a
        // process suspended holding that write lock on an app-group database;
        // docs/mls-core.md §Storage layout). A store that does hold
        // one commits the delete and erases it from the file here, before
        // the groups load, so the read of every group never runs inside it.
        //
        // Best effort: the old record does nothing for the protocol, so a
        // store that cannot take the write now is still opened, with the
        // delete rolled back, and the next open tries again. The delete takes
        // the write lock without waiting, so while another process holds it
        // the open does not wait either; a full disk fails it the same way.
        // Any other failure (a store that does not read) carries on here too,
        // and fails the group load below. A notification extension's first
        // open after an update must not fail, or wait, on it.
        let storage = provider.peachy_storage();
        match storage
            .erase_signature_key_pairs()
            .and_then(|erased| storage.flush().map(|()| erased))
        {
            Ok(false) => {}
            Ok(true) => {
                if let Err(err) = storage.erase_superseded() {
                    log::warn!("peachy-mls: could not erase superseded state: {err}");
                }
            }
            Err(err) => {
                let _ = storage.rollback();
                log::warn!(
                    "peachy-mls: could not erase the signing key kept beside the seed, will retry at the next open: {err}"
                );
            }
        }

        let credential_with_key = CredentialWithKey {
            credential: Credential::from(BasicCredential::new(credential)),
            signature_key: public.to_vec().into(),
        };

        let mut client = Self {
            provider,
            signer,
            credential_with_key,
            identity,
            own_account_identity,
            identity_provider,
            rules,
            groups: BTreeMap::new(),
            dropped_group_ids: Vec::new(),
            saved_stages: std::collections::BTreeSet::new(),
            store_generation: None,
            sync_depth: 0,
            stale: false,
            live_replay: crate::call::LiveReplayWindow::new(),
            live_last_sent_ms: 0,
            typing_replay: crate::call::LiveReplayWindow::new(),
            typing_last_sent_ms: 0,
            call_media: crate::call::media::CallMediaBook::new(),
            last_refusal_authenticated: false,
            refused_commits: BTreeMap::new(),
            recovery: crate::recovery::RecoveryBook::default(),
            pending_stamps: BTreeMap::new(),
            commit_checks: BTreeMap::new(),
            stamp_stewards: BTreeMap::new(),
            steward_merges: BTreeMap::new(),
            contested_welcome: None,
            leaving: BTreeMap::new(),
            #[cfg(feature = "test-forgery")]
            welcome_bound_seen: None,
            reopen_due: true,
            reopen_handed: std::collections::HashMap::new(),
            reopen_queue: None,
            held_swept_at_ms: None,
            hold_full_told: false,
            seal_refused: std::collections::HashSet::new(),
            sealed_limits: SealedLimits::default(),
            opened_swept_at_ms: None,
            seal_grants: std::collections::HashMap::new(),
            device_seal_secret,
            #[cfg(feature = "test-forgery")]
            hands_back_no_gap: false,
            #[cfg(feature = "test-forgery")]
            sends_while_lapsed: false,
            honors_stewards: crate::steward::STEWARD_READS,
            adopted_own_trust: crate::own_devices::AdoptedOwnTrust::default(),
            client_refusals: crate::client_refusals::ClientRefusals::default(),
        };
        // Read BEFORE the groups are: a commit another process makes while
        // they load moves it, and the first write door loads them again.
        client.store_generation = client.provider.peachy_storage().foreign_generation()?;
        client.reopen_groups()?;
        client.set_aside_leaving()?;
        // Only while version-1 records are left, and never waiting for
        // another connection's write lock: a notification extension's open
        // must not fail or wait on it, and the next open carries them. Under
        // the lock, `synced` loads what another process committed first, so
        // a second process opening at once finds the records it carried.
        // Best effort, as the erase above: a carry that fails is rolled back
        // whole by `synced`, the open goes on, and the next open tries again.
        let storage = client.provider.peachy_storage();
        if storage.holds_account_leaf_records_v1()? && storage.try_begin_write()? {
            if let Err(err) = client.synced(|client| client.carry_leaf_records_v1()) {
                log::warn!(
                    "peachy-mls: could not carry the version-1 leaf records, will retry at the next open: {err}"
                );
            }
        }
        client.flush()?;
        Ok(client)
    }

    /// Run a door that writes group state as one step against the store
    /// (§A store two processes share): take the store's write lock, load
    /// the groups again if another process has committed since they were
    /// loaded, act, and close the transaction on every outcome.
    ///
    /// A door called from inside another (a merge from the commit door)
    /// runs inside the outer one's check. The doors' own flushes come at
    /// their ends, so no write follows a flush inside one door; the flush
    /// here closes what an early refusal left open, the write lock taken
    /// for a door that then wrote nothing included.
    ///
    /// **How the transaction closes depends on how the door ended.**
    /// - It returned `Ok`, or refused with every step of the store's
    ///   behind it (a stage door's refusal, a commit or proposal whose key
    ///   was spent before a policy said no, a Welcome whose key package was
    ///   spent): COMMIT. Those writes are whole and deliberate. An
    ///   application message is the exception, and its door rolls back
    ///   itself ([`Self::process_whole`]).
    /// - A step of the store failed on the way (a refused write, a failed
    ///   read, a value that did not decode; `storage.rs` §A step that fails
    ///   part-way), or the commit itself failed: ROLLBACK, and load the
    ///   groups again from what the store holds, so that this client and
    ///   the store agree on the last whole operation and a retry starts
    ///   from it. Committing there kept a tree that had advanced over
    ///   secrets that had not, and no retry repaired it.
    /// - It panicked: ROLLBACK, and mark the groups stale so the next door
    ///   loads them again before it acts. The depth is put back first, so
    ///   the next door takes the write lock and checks the store as every
    ///   door does; a depth left at 1 had turned both off for the life of
    ///   the client. The panic then goes on to the caller.
    pub(crate) fn synced<T>(&mut self, door: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        if self.sync_depth > 0 {
            return door(self);
        }
        // A step an earlier call outside this wrapper lost is not carried
        // into this door's transaction.
        if self.provider.peachy_storage().holds_failed_step() {
            let _ = self.provider.peachy_storage().rollback();
        }
        self.provider.peachy_storage().begin_write()?;
        if let Err(err) = self.sync_with_store() {
            let _ = self.flush();
            return Err(err);
        }
        let faults = self.provider.peachy_storage().fault_count();
        self.sync_depth = 1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| door(self)));
        self.sync_depth = 0;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(payload) => {
                self.abandon_open_writes();
                std::panic::resume_unwind(payload)
            }
        };
        if outcome.is_err() && self.provider.peachy_storage().fault_count() != faults {
            self.roll_back_to_store();
            return outcome;
        }
        let closed = self.flush();
        if closed.is_err() {
            self.roll_back_to_store();
        }
        match (outcome, closed) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(err), _) | (Ok(_), Err(err)) => Err(err),
        }
    }

    /// Discard what the store holds open and load the groups again from
    /// what it committed ([`Self::synced`]). A reload that cannot finish
    /// leaves the groups marked stale, for the next write door to load
    /// again under the write lock, or to refuse if it cannot either.
    fn roll_back_to_store(&mut self) {
        let _ = self.provider.peachy_storage().rollback();
        // The generation first and the groups second, as at open: a commit
        // landing between the two moves the generation past the value kept,
        // and the next door loads again.
        let reloaded = self
            .provider
            .peachy_storage()
            .foreign_generation()
            .map_err(Error::from)
            .and_then(|now| self.reload_groups().map(|()| now));
        match reloaded {
            Ok(now) => {
                self.store_generation = now;
                self.stale = false;
            }
            Err(_) => self.stale = true,
        }
    }

    /// Load the groups again if another process has committed to the store
    /// since they were loaded, under the write lock like any door, and write
    /// nothing. For a read that must not answer from a group another process
    /// has moved past: a call's keys, read while the notification extension
    /// may have processed a removal (`docs/mls-core.md` §A store two
    /// processes share). The C ABI's read doors reach it through
    /// [`Self::refresh_if_moved`], only when the store moved.
    pub fn catch_up_with_store(&mut self) -> Result<()> {
        self.synced(|_| Ok(()))
    }

    /// [`Self::catch_up_with_store`], only when it has something to do: the
    /// store's generation is read first, without the write lock, and the
    /// groups are loaded again under the lock only when another process has
    /// committed since they were loaded, or they are stale. For the read
    /// doors (the roster, the epoch, the exporters, a call's keys, a seat
    /// ask's verdict), so none of them answers from a group another process
    /// has moved past, and none takes the write lock when nothing moved.
    /// A backend with no generation (`MemoryKv`, the wasm `CacheKv`) never
    /// reloads here.
    pub fn refresh_if_moved(&mut self) -> Result<()> {
        if self.sync_depth > 0 {
            return Ok(());
        }
        let now = self.provider.peachy_storage().foreign_generation()?;
        if self.stale || (now.is_some() && now != self.store_generation) {
            self.catch_up_with_store()?;
        }
        Ok(())
    }

    /// After a panic part-way through an operation: discard what the store
    /// holds open, and mark the groups in memory stale, so the next write
    /// door loads them again before it acts. Writes nothing.
    ///
    /// [`Self::synced`] does this itself for a door that panics. The C ABI
    /// calls it for any call that panicked, before it closes the handle
    /// (docs/mls-core.md §The C ABI contract).
    pub fn abandon_open_writes(&mut self) {
        self.sync_depth = 0;
        let _ = self.provider.peachy_storage().rollback();
        self.stale = true;
    }

    /// Load the groups again when another writer has committed to the
    /// store since they were last loaded, or when they are stale. Called
    /// under the write lock ([`Self::synced`]), so what it loads is what the
    /// door writes over.
    fn sync_with_store(&mut self) -> Result<()> {
        let now = self.provider.peachy_storage().foreign_generation()?;
        if !self.stale && (now.is_none() || now == self.store_generation) {
            return Ok(());
        }
        self.reload_groups()?;
        self.store_generation = now;
        self.stale = false;
        // ANOTHER PROCESS WROTE (the notification extension holding what
        // this one has not met): what opens now is judged again.
        self.reopen_anew();
        Ok(())
    }

    /// Replace every group in memory with the store's copy: the groups the
    /// store's index names, as another process left them, its joins in and
    /// its forgets out. Writes nothing, so it repairs nothing either: what
    /// [`Self::reopen_groups`] repairs at open waits for the next open.
    ///
    /// A staged commit is kept as what it was here. One this client staged
    /// and still holds is its own live stage, merged or cleared by the
    /// verdict it is waiting for (the stage is in the stored group, so the
    /// reload keeps it). One that appears here and was not this client's is
    /// a saved commit, as at open: another process's stage, which this one
    /// never settles. A stage gone from the store was decided elsewhere, and
    /// a merge of it is refused for having nothing staged.
    fn reload_groups(&mut self) -> Result<()> {
        let mut groups = BTreeMap::new();
        for group_id in self.provider.peachy_storage().remembered_group_ids()? {
            match MlsGroup::load(self.provider.storage(), &GroupId::from_slice(&group_id)) {
                Ok(Some(group)) => {
                    groups.insert(group_id, group);
                }
                // A half-written create, or a torn store: left for the next
                // open, which forgets it loudly (`reopen_groups`).
                Ok(None) => {}
                Err(err) => {
                    return Err(Error::Mls(format!(
                        "could not reload a stored group: {err}"
                    )))
                }
            }
        }
        let mut saved = std::collections::BTreeSet::new();
        for (group_id, group) in &groups {
            if group.pending_commit().is_none() {
                continue;
            }
            let live_here = !self.saved_stages.contains(group_id)
                && self
                    .groups
                    .get(group_id)
                    .is_some_and(|held| held.pending_commit().is_some());
            if !live_here {
                saved.insert(group_id.clone());
            }
        }
        self.refused_commits
            .retain(|group_id, _| groups.contains_key(group_id));
        self.saved_stages = saved;
        self.groups = groups;
        self.set_aside_leaving()
    }

    /// Move every group with a leaving record out of [`Self::groups`] into
    /// [`Self::leaving`], after the groups were loaded from the store (every
    /// group the store's index names, a leaving one included).
    fn set_aside_leaving(&mut self) -> Result<()> {
        self.leaving.clear();
        let mut aside = Vec::new();
        for group_id in self.groups.keys() {
            if self.provider.peachy_storage().leaving(group_id)?.is_some() {
                aside.push(group_id.clone());
            }
        }
        for group_id in aside {
            if let Some(group) = self.groups.remove(&group_id) {
                self.refused_commits.remove(&group_id);
                self.saved_stages.remove(&group_id);
                self.leaving.insert(group_id, group);
            }
        }
        Ok(())
    }

    /// Load every group named in the store's own index.
    ///
    /// An id in the index with no loadable group behind it is dropped from the
    /// index rather than reported: that is what a half-written create looks
    /// like after a crash (`mls/core/src/storage.rs`, "Durability, and the
    /// window"), the group never existed as far as any peer is concerned, and
    /// carrying the stale id forward would leave the one thing a later Welcome
    /// for the same id would collide with.
    ///
    /// **It is dropped LOUDLY.** That same `Ok(None)` is also what a TORN store
    /// looks like — a write batch that reached the disk in pieces, which the
    /// web's IndexedDB backend could produce until its drain became one
    /// transaction (the host store's `writeBatch` MUST be atomic,
    /// docs/mls-core.md §wasm binding). In that case the id names a
    /// group this device really was in,
    /// and forgetting it in silence is a conversation that stops working with
    /// no event anywhere. So it goes to the `log` facade at ERROR and is kept
    /// in [`Self::dropped_group_ids`] for a binding to surface. Not an `Err`:
    /// refusing to open the client would take every OTHER group down with it,
    /// and the recovery for the lost one is a fresh Welcome either way.
    ///
    /// A **pending commit** found on a reopened group is KEPT, and noted as
    /// saved (§A commit saved across a restart): it waits for
    /// [`Self::settle_saved_commit`] or its own echo, and the open writes
    /// nothing for it. Clearing it here turned a commit the delivery service
    /// had taken into a rejoin.
    ///
    /// **Every write comes after every read.** The groups are all loaded
    /// first; only then are the stored configs upgraded and the dropped ids
    /// forgotten, and the whole is committed at once. On SQLite the first write takes the file's write
    /// lock, so a write made part-way through the loop would hold it across
    /// the load of every later group (docs/mls-core.md §Storage
    /// layout). An open that finds nothing to repair writes nothing.
    ///
    /// **One that does repairs under the write lock, from one snapshot.**
    /// The pass reads without the lock, each read its own snapshot, so
    /// another process (the notification extension forgetting a group) can
    /// commit part-way through it. Before writing, the open takes the write
    /// lock and asks the store's generation again: if another writer has
    /// committed since it was read at the top, the pass runs again under the
    /// lock (holding it across that load, only then), and what it writes
    /// follows from what the lock holds.
    fn reopen_groups(&mut self) -> Result<()> {
        let (mut outdated, mut forgotten, mut unrecorded) = self.reopen_pass()?;
        if outdated.is_empty() && forgotten.is_empty() && unrecorded.is_empty() {
            return Ok(());
        }
        self.provider.peachy_storage().begin_write()?;
        let now = self.provider.peachy_storage().foreign_generation()?;
        if now != self.store_generation {
            self.store_generation = now;
            (outdated, forgotten, unrecorded) = self.reopen_pass()?;
        }
        for (group_id, epoch) in &unrecorded {
            self.provider
                .peachy_storage()
                .raise_epoch_mark(group_id, *epoch)?;
            self.provider
                .peachy_storage()
                .set_head_state(group_id, HeadState::Lapsed)?;
        }
        let wanted = Self::join_config();
        for group_id in &outdated {
            if let Some(group) = self.groups.get_mut(group_id) {
                // The past epochs are cut to the bound BEFORE the config is
                // rewritten, newest kept. The rewrite resizes the store too,
                // but OpenMLS's resize, shrinking a store that is not full,
                // keeps the OLDEST epochs and drops the newest — the ones a
                // message in flight still needs. Cut first, the resize finds
                // nothing to drop. Keeping every epoch whatever its age, then
                // the newest RETAINED_PAST_EPOCHS, is the deletion's own
                // count rule with no time rule.
                group
                    .delete_past_epoch_secrets(
                        &self.provider,
                        PastEpochDeletion::older_than_duration(std::time::Duration::MAX)
                            .max_past_epochs(RETAINED_PAST_EPOCHS),
                    )
                    .map_err(|err| {
                        Error::Mls(format!("could not cut a group's past epochs: {err}"))
                    })?;
                group
                    .set_configuration(self.provider.storage(), &wanted)
                    .map_err(|err| {
                        Error::Mls(format!(
                            "could not upgrade a group's stored join config: {err}"
                        ))
                    })?;
            }
        }
        for group_id in &forgotten {
            self.provider.peachy_storage().forget_group(group_id)?;
            self.provider
                .peachy_storage()
                .set_head_state(group_id, HeadState::Unrecorded)?;
        }
        self.flushed_and_erased(())
    }

    /// The read pass of [`Self::reopen_groups`]: load every group the index
    /// names into memory (replacing what an earlier pass loaded), and return
    /// what the open repairs: the groups whose stored config is outdated,
    /// the ids with no state behind them, and the copies with no head record
    /// (with their epochs). Writes nothing.
    #[allow(clippy::type_complexity)]
    fn reopen_pass(&mut self) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<(Vec<u8>, u64)>)> {
        self.groups.clear();
        self.dropped_group_ids.clear();
        let storage = self.provider.peachy_storage();
        let mut staged = Vec::new();
        let mut outdated = Vec::new();
        let mut forgotten = Vec::new();
        let mut unrecorded = Vec::new();
        for group_id in storage.remembered_group_ids()? {
            match MlsGroup::load(self.provider.storage(), &GroupId::from_slice(&group_id)) {
                Ok(Some(group)) => {
                    if group.pending_commit().is_some() {
                        staged.push(group_id.clone());
                    }
                    // THE HANDSHAKE UPGRADE (see [`PEACHY_WIRE_FORMAT_POLICY`]).
                    // OpenMLS reads the STORED join config, not `join_config()`,
                    // so a group whose store holds another policy would go
                    // on with whatever policy is stored — plaintext
                    // handshakes out, or plaintext handshakes accepted in — and
                    // the change would reach new conversations only, when the
                    // ones people are actually in are the old ones. The same
                    // trap `encrypt_padded_to` works around for padding, and it
                    // is caught in the same place for the same reason: once, at
                    // open, before anything can build or process a commit.
                    //
                    // The WHOLE policy is compared, both halves: a group stored
                    // with sealed outgoing and mixed incoming would take a
                    // plaintext handshake, and comparing the outgoing half alone
                    // would leave it doing so for ever. Rewriting the whole
                    // config rather than one field is the point too —
                    // `join_config()` is the one description of what a Peachy
                    // group is, so a device that has been through this holds no
                    // field a fresh join would not.
                    //
                    // THE SENDER RATCHET rides the same rewrite
                    // ([`OUT_OF_ORDER_TOLERANCE`]): a group joined before the
                    // window widened would otherwise keep OpenMLS's five for
                    // ever, and go on losing the rows a catch-up reaches after
                    // the lane.
                    //
                    // And THE PAST-EPOCH BOUND ([`RETAINED_PAST_EPOCHS`]): a
                    // group stored under a wider one keeps that many epochs'
                    // keys until something rewrites its config, and the
                    // rewrite is what drops the extra ones.
                    let wanted = Self::join_config();
                    if group.configuration().wire_format_policy() != wanted.wire_format_policy()
                        || group.configuration().sender_ratchet_configuration()
                            != wanted.sender_ratchet_configuration()
                        || group.past_epoch_deletion_policy()
                            != &PastEpochDeletionPolicy::MaxEpochs(RETAINED_PAST_EPOCHS)
                    {
                        outdated.push(group_id.clone());
                    }
                    // A COPY WITH NO HEAD RECORD was held from before the
                    // record was kept: judged like a lapsed one, so its epoch
                    // goes into the mark the way a lapse puts it there.
                    if storage.head_state(&group_id)? == HeadState::Unrecorded {
                        unrecorded.push((group_id.clone(), group.epoch().as_u64()));
                    }
                    self.groups.insert(group_id, group);
                }
                Ok(None) => {
                    log::error!(
                        "peachy-mls: the store remembers a group but holds no state for it — \
                         forgetting it. A half-written create looks like this, and so does a \
                         TORN WRITE BATCH; if this device was really in that group, it can only \
                         come back through a fresh Welcome. Which group is in the dropped ids \
                         the caller reads, not here."
                    );
                    self.dropped_group_ids.push(group_id.clone());
                    forgotten.push(group_id);
                }
                Err(err) => {
                    return Err(Error::Mls(format!(
                        "could not reopen a stored group: {err}"
                    )))
                }
            }
        }

        if !staged.is_empty() {
            // A fixed sentence: nothing that names the group (the crate's
            // rule on logs, in lib.rs).
            log::info!(
                "peachy-mls: a staged commit found at open is kept until the group's head \
                 settles it"
            );
        }
        self.saved_stages = staged.into_iter().collect();
        Ok((outdated, forgotten, unrecorded))
    }

    /// Make everything this client has written durable.
    ///
    /// Called at the end of every operation that changes state. Public because
    /// the wasm binding's flush is driven from JavaScript, which has to be able
    /// to say when.
    pub fn flush(&self) -> Result<()> {
        self.provider.peachy_storage().flush()?;
        Ok(())
    }

    /// `value`, once everything written for it is durable.
    pub(crate) fn flushed<T>(&self, value: T) -> Result<T> {
        self.flush()?;
        Ok(value)
    }

    /// [`Self::flush`], then erase from the backend what the operation
    /// replaced: the previous epoch's secrets, a spent ratchet key, a
    /// consumed key package (§Storage, and `mls/core/src/sqlite.rs`
    /// §Erasing what an operation replaced).
    ///
    /// Every operation that leaves a secret behind ends here rather than at
    /// [`Self::flushed`]. The erase cannot fail the operation: the state is
    /// committed by then, and an error here would tell the caller an epoch
    /// it is already in did not happen. A backend that could not finish says
    /// so and retries at its next flush.
    fn flushed_and_erased<T>(&self, value: T) -> Result<T> {
        self.flush()?;
        self.erase_superseded();
        Ok(value)
    }

    /// Every stage door's tail (§The commit lifecycle): commit what the stage
    /// wrote and erase what it replaced, whatever the stage's `outcome` was.
    ///
    /// A refusal is committed too. The doors write before they can refuse —
    /// the padding set on the group's config and put back, a commit staged
    /// and then cleared because the receivers would refuse it — and a
    /// refusal that returned with those writes uncommitted would hold the
    /// store's write lock after the call, as an uncommitted stage would for
    /// the whole round trip to the delivery service.
    ///
    /// When the commit itself fails after a successful stage, the caller
    /// hears that error and owes the group no verdict, so the stage is
    /// cleared rather than left for a caller who does not know it is there.
    /// When both fail, the stage's own error is the one reported.
    fn stage_committed(
        &mut self,
        group_id: &[u8],
        outcome: Result<CommitBundle>,
    ) -> Result<CommitBundle> {
        if let Ok(bundle) = &outcome {
            // A stage made here is this run's own, with a verdict it will
            // hear: no longer one saved from an earlier run. Its bytes are
            // kept beside it, for the echo of a commit saved across a
            // restart (§A commit saved across a restart).
            self.saved_stages.remove(group_id);
            let digest: [u8; 32] = sha2::Sha256::digest(&bundle.commit).into();
            if let Err(err) = self
                .provider
                .peachy_storage()
                .set_staged_commit(group_id, &digest)
            {
                if let Some(group) = self.groups.get_mut(group_id) {
                    let _ = group.clear_pending_commit(self.provider.storage());
                }
                let _ = self.flush();
                return Err(err.into());
            }
        }
        match (outcome, self.flushed_and_erased(())) {
            (outcome, Ok(())) => outcome,
            (Err(refused), Err(_)) => {
                log::warn!("peachy-mls: could not commit what a refused stage wrote");
                Err(refused)
            }
            (Ok(_), Err(err)) => {
                if let Some(group) = self.groups.get_mut(group_id) {
                    let _ = group.clear_pending_commit(self.provider.storage());
                }
                let _ = self.flush();
                Err(err)
            }
        }
    }

    fn erase_superseded(&self) {
        match self.provider.peachy_storage().erase_superseded() {
            Ok(true) => {}
            // A fixed sentence, as every log line in the crate.
            Ok(false) => log::debug!(
                "peachy-mls: the store was busy; superseded state is erased at the next flush"
            ),
            Err(err) => log::warn!("peachy-mls: could not erase superseded state: {err}"),
        }
    }

    /// This device's Peachy-owned storage, for the modules that keep a record
    /// of their own beside the groups (`crate::own_devices`).
    pub(crate) fn peachy_storage(&self) -> &crate::storage::PeachyStorage {
        self.provider.peachy_storage()
    }

    /// This device's verified identity.
    pub fn identity(&self) -> &PeachyIdentity {
        &self.identity
    }

    pub fn rules(&self) -> &PeachyMlsRules {
        &self.rules
    }

    /// The group ids this client currently holds state for, less those it is
    /// leaving ([`Self::begin_leave`]).
    pub fn group_ids(&self) -> Vec<Vec<u8>> {
        self.groups.keys().cloned().collect()
    }

    /// Group ids this client's store remembered and could not open, dropped
    /// when the client was built. Empty in the ordinary case.
    ///
    /// The same event `reopen_groups` logs, as data a binding can put
    /// in front of somebody. It is deliberately not an error: see that method.
    pub fn dropped_group_ids(&self) -> &[Vec<u8>] {
        &self.dropped_group_ids
    }

    // ---- Key packages -------------------------------------------------------

    /// Mint a key package for somebody else to add us with.
    ///
    /// Returns a serialized `MLSMessage`, which is what a key-package directory
    /// would publish. Each call generates fresh init and encryption keys and
    /// leaves the private halves in this client's storage, so a key package is
    /// single-use: publishing N of them is how a person can be added N times
    /// while offline.
    pub fn generate_key_package(&self) -> Result<Vec<u8>> {
        Ok(self.generate_key_package_with_ref()?.0)
    }

    /// The same key package, plus the RFC 9420 KeyPackageRef that names it.
    ///
    /// `MakeKeyPackageRef(value) = RefHash("MLS 1.0 KeyPackage Reference",
    /// value)` over the TLS-serialised KeyPackage — §5.2, and note that the
    /// hashed value is the bare KeyPackage and NOT the `MlsMessage` wrapper
    /// this returns beside it. The two differ by a framing header, so a caller
    /// hashing the published bytes itself gets a plausible-looking value that
    /// is not the reference any other MLS implementation will compute.
    ///
    /// Which is exactly why this exists. A key-package DIRECTORY needs a name
    /// for each package — Peachy's is `key_package_ref` on
    /// `PublishKeyPackages` (docs/delivery.md §The KeyPackage
    /// lifecycle), the idempotency key that stops a device republishing its
    /// pool from growing it. The server has no MLS implementation and takes
    /// the value on trust, so nothing would catch a client that invented one;
    /// it would simply publish a fresh row per call forever. Computing it in
    /// the one place that already holds the package is how all three bindings
    /// get the same answer.
    ///
    /// Refused as [`CredentialRejection::NotApproved`] while this device's
    /// credential carries no account certificate: every adder would refuse
    /// the package, so publishing it only fills a directory with dead rows.
    pub fn generate_key_package_with_ref(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if self.identity.account_key.is_none() {
            return Err(CredentialRejection::NotApproved.into());
        }
        self.build_key_package(false)
    }

    /// A LAST-RESORT key package and its ref: the one a key-package directory
    /// hands out when this device's one-time packages have run out, and which
    /// opens any number of Welcomes until it is rotated and archived.
    ///
    /// It carries the `last_resort` KeyPackage extension (0x000A), the
    /// marking for the reuse RFC 9420 §16.8 allows a "last resort" package,
    /// and that marking is the whole mechanism: OpenMLS deletes a package's
    /// private half from storage the first time a Welcome opens it UNLESS the
    /// package carries the extension (`openmls` 0.9,
    /// `group/mls_group/creation.rs`: `if !key_package_bundle.key_package().last_resort()`).
    /// Unmarked, the "last-resort" package a device published opened exactly
    /// one Welcome, and every add after that failed with "No matching key
    /// package" while the directory, correctly, kept serving it.
    ///
    /// The directory serves it only when no one-time package is left, the
    /// device keeps it on use, and it is rotated every two days. This records
    /// the package in the device's last-resort index and prunes the index on
    /// the archive rule
    /// ([`LAST_RESORT_ARCHIVE_AGE_SECONDS`]); [`Self::last_resort_rotation_due`]
    /// is the rotation clock.
    ///
    /// Refused, like [`Self::generate_key_package_with_ref`], while this device
    /// carries no account certificate.
    pub fn generate_last_resort_key_package_with_ref(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if self.identity.account_key.is_none() {
            return Err(CredentialRejection::NotApproved.into());
        }
        self.build_key_package(true)
    }

    /// Whether this device owes the directory a new last-resort key package:
    /// it holds none this build minted, or its newest is
    /// [`LAST_RESORT_ROTATION_INTERVAL_SECONDS`] old or more.
    ///
    /// A clock that went backwards is due too. A caller publishes
    /// the replacement with `last_resort` set, which retires its predecessor
    /// at the directory; this device keeps the predecessor's private half.
    pub fn last_resort_rotation_due(&self) -> Result<bool> {
        let newest = self
            .provider
            .peachy_storage()
            .last_resorts()?
            .into_iter()
            .map(|(_, at)| at)
            .max();
        let Some(at) = newest else { return Ok(true) };
        let age = self.identity_provider.now_unix() - at;
        Ok(!(0..LAST_RESORT_ROTATION_INTERVAL_SECONDS).contains(&age))
    }

    /// Delete the private halves of replaced last-resort key packages no
    /// in-flight Welcome can still need: keep the newest; of the rest, consider only those older than
    /// [`LAST_RESORT_ARCHIVE_AGE_SECONDS`]; delete all of those but the
    /// youngest. Run after every mint. True when it deleted one.
    fn prune_last_resorts(&self) -> Result<bool> {
        let storage = self.provider.peachy_storage();
        let mut held = storage.last_resorts()?;
        // Newest first; ties broken on the ref so the order is total.
        held.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
        let now = self.identity_provider.now_unix();
        let stale = held
            .iter()
            .skip(1)
            .filter(|(_, at)| now - at > LAST_RESORT_ARCHIVE_AGE_SECONDS)
            .skip(1);
        let mut pruned = false;
        for (reference, _) in stale {
            // A KeyPackageRef is a TLS `opaque<V>`; OpenMLS builds one from raw
            // bytes only under its test features, so the bytes go back in
            // through its own decoder.
            let encoded = tls_codec::Serialize::tls_serialize_detached(&tls_codec::VLBytes::new(
                reference.clone(),
            ))?;
            let reference_typed = KeyPackageRef::tls_deserialize_exact(encoded)?;
            self.provider
                .storage()
                .delete_key_package(&reference_typed)?;
            storage.forget_last_resort(reference)?;
            // Nothing can open those Welcomes now; the record of taking
            // them goes with the key.
            storage.forget_welcomes_taken_with(reference)?;
            pruned = true;
        }
        Ok(pruned)
    }

    /// A key package from a device with NO account certificate, which
    /// [`Self::generate_key_package`] refuses to make. For the golden fixture
    /// and tests only: it is how a case proves every adder refuses one.
    #[cfg(any(feature = "fixture", feature = "test-forgery"))]
    #[doc(hidden)]
    pub fn forge_unapproved_key_package(&self) -> Result<Vec<u8>> {
        Ok(self.build_key_package(false)?.0)
    }

    /// A key package of this device whose leaf lifetime is
    /// `[not_before, not_after]` (unix seconds, the WALL clock OpenMLS reads,
    /// not this client's injected one), which no product path chooses: every
    /// published package takes OpenMLS's default lifetime. For a test that
    /// hands members an add whose card has run out. Its private halves are
    /// kept, as a published package's are, so a Welcome to it opens.
    /// Test-only; see `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_key_package_with_lifetime(
        &self,
        not_before: u64,
        not_after: u64,
    ) -> Result<Vec<u8>> {
        let bundle: KeyPackageBundle = KeyPackage::builder()
            .leaf_node_capabilities(peachy_leaf_capabilities())
            .key_package_lifetime(openmls::prelude::Lifetime::init(not_before, not_after))
            .build(
                PEACHY_CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .map_err(mls_err)?;
        let bytes = MlsMessageOut::from(bundle.key_package().clone())
            .to_bytes()
            .map_err(mls_err)?;
        self.flushed(bytes)
    }

    fn build_key_package(&self, last_resort: bool) -> Result<(Vec<u8>, Vec<u8>)> {
        let builder = KeyPackage::builder()
            // The same capability the group creator's leaf carries, for the
            // same reason: a key package whose leaf does not advertise
            // `peachy_group_meta` cannot be added to a group that has the
            // extension set, so the capability has to be on every package this
            // device ever publishes rather than on the ones it guesses will
            // need it.
            .leaf_node_capabilities(if last_resort {
                self.last_resort_leaf_capabilities()
            } else {
                self.leaf_capabilities()
            });
        let builder = if last_resort {
            builder.mark_as_last_resort()
        } else {
            builder
        };
        let bundle: KeyPackageBundle = builder
            .build(
                PEACHY_CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .map_err(mls_err)?;
        Self::refuse_oversized_own_leaf(bundle.key_package().leaf_node())?;
        let key_package_ref = bundle
            .key_package()
            .hash_ref(self.provider.crypto())
            .map_err(mls_err)?
            .as_slice()
            .to_vec();
        let bytes = MlsMessageOut::from(bundle.key_package().clone())
            .to_bytes()
            .map_err(mls_err)?;
        let pruned = if last_resort {
            self.provider
                .peachy_storage()
                .note_last_resort(&key_package_ref, self.identity_provider.now_unix())?;
            self.prune_last_resorts()?
        } else {
            false
        };
        // Flushed before it is returned, and this one matters more than most:
        // the private init and encryption halves of a published key package
        // live only in this store, so a key package handed out and then lost
        // is a Welcome nobody can open. A replaced last-resort package's
        // private halves, deleted above, are erased as well.
        if pruned {
            self.flushed_and_erased((bytes, key_package_ref))
        } else {
            self.flushed((bytes, key_package_ref))
        }
    }

    // ---- Group lifecycle ----------------------------------------------------

    /// Create a group with this client as its only member.
    ///
    /// Refused as [`CredentialRejection::NotApproved`] while this device's
    /// credential carries no account certificate: every peer would refuse its
    /// leaf, so a group it founded is a group nobody could join.
    pub fn create_group(&mut self, group_id: &[u8]) -> Result<()> {
        self.synced(|client| client.create_group_now(group_id))
    }

    fn create_group_now(&mut self, group_id: &[u8]) -> Result<()> {
        if group_id.is_empty() {
            return Err(Error::invalid("a group id must not be empty"));
        }
        // A device seal names the group in a fixed 64 bytes
        // ([`crate::device_seal::DEVICE_SEAL_MAX_GROUP_ID_BYTES`]): a group
        // with a longer id could carry none.
        if group_id.len() > crate::device_seal::DEVICE_SEAL_MAX_GROUP_ID_BYTES {
            return Err(Error::invalid("a group id must be at most 64 bytes"));
        }
        if self.identity.account_key.is_none() {
            return Err(CredentialRejection::NotApproved.into());
        }
        if self.groups.contains_key(group_id) {
            return Err(Error::invalid("a group with that id is already open"));
        }
        let config = Self::create_config(self.leaf_capabilities());
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id),
            self.credential_with_key.clone(),
        )
        .map_err(mls_err)?;
        self.groups.insert(group_id.to_vec(), group);
        self.provider.peachy_storage().remember_group(group_id)?;
        // A group this device founds is its own: nobody else's word made
        // it, so it is confirmed from its first epoch, and that epoch's
        // verifier is the first a trailing head is judged against.
        self.provider
            .peachy_storage()
            .forget_copy_records(group_id)?;
        self.provider
            .peachy_storage()
            .set_head_state(group_id, HeadState::Confirmed)?;
        self.steward_merges.remove(group_id);
        self.note_copy_epoch(group_id)?;
        self.note_fresh_leaf(group_id)?;
        self.flush()
    }

    /// Join a group from a Welcome. Returns the group id joined.
    ///
    /// The ratchet tree comes in the Welcome's `ratchet_tree` extension
    /// (`create_config` sets it), so no out-of-band tree is needed.
    /// Every member of the joined group is identity-checked before the group is
    /// kept: joining a room and *then* discovering you cannot verify who is in
    /// it is a door Peachy does not want open.
    ///
    /// **A Welcome into a group this client is already in is refused**
    /// ([`Error::AlreadyAMember`]) and the live group is left exactly as it
    /// was. That case is not hypothetical — two members racing an add produce
    /// two Welcomes against two different key packages of the same device, and
    /// the loser's is still a real Welcome that can reach its recipient late.
    /// Acting on it would replace a group at epoch N with a fresh one at
    /// whatever epoch the stale Welcome sealed, losing every epoch between; the
    /// device would then fail to read its own conversation and look corrupt
    /// rather than stale.
    ///
    /// OpenMLS refuses it too, from storage (`WelcomeError::GroupAlreadyExists`
    /// — so the live group was never really in danger here), and that refusal
    /// is translated rather than passed through as an opaque
    /// [`Error::Mls`] string. The translation is the point: the caller's right
    /// move on a duplicate is to do nothing at all, and a caller that cannot
    /// tell it from "this Welcome will not open" either logs noise on every
    /// race or swallows every failure to avoid the noise.
    /// The in-memory check below is kept beside it because it says what this
    /// crate promises, rather than relying on what a dependency happens to do.
    ///
    /// **"Already in" means ACTIVE.** A group this client holds only because a
    /// commit removed it — `removed_self`, state kept, `is_active()` false — is
    /// not a group it is in, and a Welcome into it REPLACES that state. That is
    /// the re-seat of an evicted device, and it is the only way back in: the
    /// inactive state can read nothing new and send nothing at all.
    ///
    /// **A Welcome at or below the group's epoch mark is refused**
    /// ([`Error::AlreadyAMember`]), whether this device holds the group now,
    /// active or not, or forgot it; and so is a Welcome it already took
    /// through a last-resort key package. The mark is the highest epoch the
    /// group's head vouched for on this device ([`Self::epoch_mark`]), kept
    /// for good. A re-add always comes at a later epoch than the one this
    /// device last held, since at least the commit that re-adds it lies
    /// between, so only a replayed Welcome, or one of a branch beside the
    /// group's, is refused.
    ///
    /// **The key package is spent either way, including on a refusal**, and
    /// that is OpenMLS' shape rather than a choice here: the group id lives
    /// inside the Welcome's encrypted GroupInfo, so nothing can be known about
    /// a Welcome until the key material that opens it has been consumed and
    /// deleted (`StagedWelcome::new_from_welcome` says so in its own doc). One
    /// one-time package per duplicate Welcome, which is what the clients'
    /// key-package replenishment exists to top up.
    ///
    /// **Every outcome is flushed, a refusal included**, as
    /// [`Self::process_any`] does. Spending the key package is a write, and
    /// every refusal past that point would otherwise return with the store's
    /// transaction open: on SQLite, its write lock held after the call, so
    /// every other connection to the file (a notification extension) could
    /// not write until some unrelated operation flushed. The spent package is
    /// meant to stay spent, so committing it is the right half-state, and its
    /// private halves are erased like any consumed package's. A refusal that
    /// wrote nothing (bytes that are not a Welcome) commits nothing.
    pub fn join_from_welcome(&mut self, welcome: &[u8]) -> Result<Vec<u8>> {
        self.synced(|client| {
            let outcome = client.join_from_welcome_inner(welcome, None, None);
            client.flushed_and_erased(())?;
            outcome
        })
    }

    /// The group a Welcome is for, and the epoch it would seat this device
    /// at, read without taking it: what a caller needs to find the group's
    /// head before [`Self::join_from_welcome_at_head`]. Both are as the
    /// Welcome claims them, unverified; that door verifies them.
    ///
    /// The group id lives inside the Welcome's encrypted GroupInfo, so the
    /// Welcome is opened with this device's key package to read it, and
    /// nothing that wrote is kept: the store's transaction is rolled back, so
    /// a one-time package is still there for the door. Writes nothing, with
    /// one exception: a frame the doors would refuse (a raw Welcome among
    /// them) is refused here as well, and spends its key package as the
    /// doors do, since a caller that hears the refusal never reaches a door.
    pub fn welcome_group(&mut self, welcome: &[u8]) -> Result<(Vec<u8>, u64)> {
        if let Err(err) = crate::welcome_frame::unframe_welcome_parts(welcome) {
            return self.synced(|client| {
                let spent = client.spend_refused_frame(welcome);
                client.flushed_and_erased(())?;
                spent?;
                Err(err)
            });
        }
        if self.provider.peachy_storage().holds_failed_step() {
            let _ = self.provider.peachy_storage().rollback();
        }
        self.provider.peachy_storage().begin_write()?;
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.peek_welcome(welcome)));
        let undone = self.provider.peachy_storage().rollback();
        match outcome {
            Ok(outcome) => {
                undone?;
                outcome
            }
            Err(payload) => {
                self.abandon_open_writes();
                std::panic::resume_unwind(payload)
            }
        }
    }

    fn peek_welcome(&self, welcome: &[u8]) -> Result<(Vec<u8>, u64)> {
        let welcome = crate::welcome_frame::unframe_welcome(welcome)?;
        let message = MlsMessageIn::tls_deserialize_exact(welcome)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(Error::invalid("that message is not a Welcome"));
        };
        let builder =
            StagedWelcome::build_from_welcome(&self.provider, &Self::join_config(), welcome)
                .map_err(mls_err)?;
        let info = builder.processed_welcome().unverified_group_info();
        Ok((info.group_id().as_slice().to_vec(), info.epoch().as_u64()))
    }

    /// Join a group from a Welcome, against the group's head as the
    /// delivery service reports it (`FetchConversationHead` for
    /// [`crate::envelope::group_handle`] of the group id
    /// [`Self::welcome_group`] reads): its epoch, and the SHA-256 of that
    /// epoch's send key ([`SEND_KEY_LABEL`]). The door the apps take every
    /// Welcome through. Returns the group id joined.
    ///
    /// Everything [`Self::join_from_welcome`] checks, and the head besides.
    /// The delivery service moves a handle's head and places the Welcomes of
    /// the commit that moved it in one step, so the Welcome of a real add is
    /// never above the head, and is at the head's epoch under the head's own
    /// send key until the group moves again.
    ///
    /// - **Above the head's epoch**, or **at it under another send key**:
    ///   refused, [`Error::AlreadyAMember`]. It is no seat in the group the
    ///   delivery service holds: a group of somebody's own under the id, or a
    ///   branch beside the real one.
    /// - **At the head**: taken, and the copy is confirmed
    ///   ([`Self::confirm_head`]). An ACTIVE copy this device holds is
    ///   replaced by it, unless that copy is at the head itself, or at or
    ///   above the Welcome's epoch: a live copy never moves back. What it
    ///   changes against the copy it replaces is reported
    ///   ([`Self::join_contested_welcome`] says how).
    /// - **Below the head**: taken unconfirmed, when this device holds no
    ///   active copy. The commits since follow in its mailbox, and the copy
    ///   is confirmed once it reaches the head. With an active copy held:
    ///   refused, [`Error::AlreadyAMember`].
    ///
    /// A seat taken here raises the epoch mark to its epoch, which the head
    /// bounds. A copy no head ever matched raises no mark with its later
    /// epochs.
    ///
    /// [`Error::SettleFirst`] when the group holds a saved commit, with the
    /// key package put back: the same call succeeds once the commit is
    /// settled. Every other outcome is flushed, as [`Self::join_from_welcome`]
    /// does.
    pub fn join_from_welcome_at_head(
        &mut self,
        welcome: &[u8],
        head_epoch: u64,
        head_verifier: &[u8],
    ) -> Result<Vec<u8>> {
        self.synced(|client| {
            let outcome =
                client.join_from_welcome_inner(welcome, Some((head_epoch, head_verifier)), None);
            if matches!(outcome, Err(Error::SettleFirst)) {
                client.provider.peachy_storage().rollback()?;
                return outcome;
            }
            client.flushed_and_erased(())?;
            outcome
        })
    }

    /// [`Self::join_from_welcome_at_head`], with the delivery service's
    /// **verifier log** answer for the Welcome's own epoch (`FetchVerifierAt`
    /// for the group's handle and the epoch [`Self::welcome_group`] reads;
    /// docs/delivery.md §FetchVerifierAt): `logged_verifier`, the
    /// SHA-256 of the send key the group the server holds had at that epoch
    /// (empty when the log holds none), and `kept_from`, the lowest epoch
    /// from which the log holds every epoch up to the head (`None` when the
    /// server named none). The caller passes only an answer it got: a read
    /// that failed holds the Welcome, as an unreadable head does.
    ///
    /// It matters only for a Welcome BELOW the head, which the head alone
    /// cannot place: one from the real group that has moved on since, or one
    /// from a group somebody founded under the id at an epoch of their
    /// choosing. The log settles it:
    ///
    /// - **The Welcome's send key hashes to the logged verifier**: it is a
    ///   seat in the group the server holds, at that epoch. It is taken and
    ///   confirmed, as a Welcome at the head is: the epoch mark rises to its
    ///   epoch, and an active copy no head ever vouched for, and that is
    ///   below the Welcome's epoch, is replaced by it and drawn. An active
    ///   copy at or above the Welcome's epoch is kept: a live copy never
    ///   moves back.
    /// - **It does not**: refused, [`Error::AlreadyAMember`], as a Welcome at
    ///   the head's epoch under another send key is. It seats this device in
    ///   no group the server held.
    /// - **Nothing is logged at an epoch at or above `kept_from`**: refused,
    ///   [`Error::AlreadyAMember`]. The log holds every epoch from there, so
    ///   an honest server has a row for any epoch the real group passed
    ///   through, and a Welcome at one it has none for is from a group
    ///   somebody founded under the id.
    /// - **Nothing is logged, below `kept_from` or with no floor named**:
    ///   judged as [`Self::join_from_welcome_at_head`] judges it, and
    ///   logged as a fallback. (A Welcome placed before the log began has no
    ///   row to match, so the log cannot judge it.)
    ///
    /// A verifier of any length but 32 counts as none. Flushed as
    /// [`Self::join_from_welcome_at_head`] is.
    pub fn join_from_welcome_at_head_logged(
        &mut self,
        welcome: &[u8],
        head_epoch: u64,
        head_verifier: &[u8],
        logged_verifier: &[u8],
        kept_from: Option<u64>,
    ) -> Result<Vec<u8>> {
        let logged = LogAnswer {
            verifier: (logged_verifier.len() == 32).then_some(logged_verifier),
            kept_from,
        };
        self.synced(|client| {
            let outcome = client.join_from_welcome_inner(
                welcome,
                Some((head_epoch, head_verifier)),
                Some(logged),
            );
            if matches!(outcome, Err(Error::SettleFirst)) {
                client.provider.peachy_storage().rollback()?;
                return outcome;
            }
            client.flushed_and_erased(())?;
            outcome
        })
    }

    /// Whether the copy of `group_id` this device holds is the group's head
    /// as the delivery service reports it, and record the answer: an active
    /// copy at `head_epoch` whose send key hashes to `head_verifier` is
    /// CONFIRMED, and stays confirmed as it follows the group's commits.
    /// Answers whether the copy is confirmed now.
    ///
    /// A copy at the head is confirmed, the epoch mark is raised to its
    /// epoch, and the roster kept from an earlier forget of the group is
    /// spent: the copy names the group's people now. A confirmed copy at the
    /// head's epoch under another send key LAPSES: the epoch mark is raised
    /// to its epoch first, so no head ever lowers the mark, and the epochs it
    /// reaches after that raise nothing until a head matches it again. A head
    /// only ever changes what counts toward the mark: a copy that matched a
    /// head once keeps naming its people to the Welcome judge whatever a
    /// later head says, so no answer of the delivery service's can empty the
    /// roster a Welcome is drawn against. A head above the copy, and an
    /// inactive copy, are left as they are.
    ///
    /// **A copy no head has matched yet is judged against its own history.**
    /// The device keeps the send-key verifier of each of the last
    /// [`COPY_VERIFIERS_KEPT`](crate::storage::COPY_VERIFIERS_KEPT) epochs
    /// the copy held, so a head read before a commit this device processed
    /// (a head that trails the copy honestly) still confirms it when it
    /// names one of them. A head that names an epoch the copy held, its own
    /// included, under another send key CONTESTS the copy
    /// ([`HeadState::Contested`]): the copy stays unvouched, and a
    /// [`RejoinReport`] with `contested` set is kept for the client to say
    /// so, before any Welcome can replace it. A later head that matches its
    /// history still confirms it, and so does a merge of this device's own
    /// commit: a match takes a member of the copy's epoch to produce, a
    /// contradiction takes nobody. So the delivery service can contest a
    /// copy and later confirm it; the contested line, once kept, stays
    /// drawn, and a contest changes nothing a device enforces. A confirmed copy is
    /// judged only at its own epoch, as above. A group this device does not
    /// hold answers false.
    ///
    /// The apps call it with every head they read: the head of a Welcome's
    /// group, a sweep of every head, the fork check's. A merge of this
    /// device's own commit confirms the copy too, since the delivery service
    /// took it.
    pub fn confirm_head(
        &mut self,
        group_id: &[u8],
        head_epoch: u64,
        head_verifier: &[u8],
    ) -> Result<bool> {
        self.synced(|client| {
            let outcome = client.confirm_head_now(group_id, head_epoch, head_verifier);
            client.flush()?;
            outcome
        })
    }

    fn confirm_head_now(
        &mut self,
        group_id: &[u8],
        head_epoch: u64,
        head_verifier: &[u8],
    ) -> Result<bool> {
        let Some(group) = self.groups.get(group_id) else {
            return Ok(false);
        };
        let state = self.provider.peachy_storage().head_state(group_id)?;
        let confirmed = state == HeadState::Confirmed;
        let copy_epoch = group.epoch().as_u64();
        if !group.is_active() || head_epoch > copy_epoch {
            return Ok(confirmed);
        }
        if head_epoch == copy_epoch {
            if self.held_at_head(group_id, head_epoch, head_verifier)? {
                self.note_head_confirmed(group_id)?;
                self.provider
                    .peachy_storage()
                    .vouch_head_epoch(group_id, head_epoch)?;
                return Ok(true);
            }
            match state {
                HeadState::Confirmed => {
                    log::warn!(
                        "peachy-mls: the group's head names another send key at this copy's \
                         epoch — the copy is no longer confirmed"
                    );
                    // The epochs it reached while confirmed stay in the mark.
                    self.raise_epoch_mark_to_held(group_id)?;
                    self.provider
                        .peachy_storage()
                        .set_head_state(group_id, HeadState::Lapsed)?;
                }
                HeadState::Unconfirmed => self.contest_copy(group_id)?,
                _ => {}
            }
            return Ok(false);
        }
        // A head the copy has passed: judged against what the copy held at
        // that epoch, when no head has matched the copy yet. One that names
        // the copy's own verifier there vouches for that epoch whatever the
        // copy's state ([`Self::head_rolled_back`]).
        let held = self
            .provider
            .peachy_storage()
            .copy_verifiers(group_id)?
            .into_iter()
            .find(|(epoch, _)| *epoch == head_epoch);
        if matches!(&held, Some((_, verifier)) if verifier.as_slice() == head_verifier) {
            self.provider
                .peachy_storage()
                .vouch_head_epoch(group_id, head_epoch)?;
        }
        if !matches!(state, HeadState::Unconfirmed | HeadState::Contested) {
            return Ok(confirmed);
        }
        match held {
            Some((_, verifier)) if verifier.as_slice() == head_verifier => {
                self.note_head_confirmed(group_id)?;
                Ok(true)
            }
            Some(_) => {
                self.contest_copy(group_id)?;
                Ok(false)
            }
            None => Ok(false),
        }
    }

    /// Whether the group's head, as the delivery service reports it, was
    /// ROLLED BACK below the copy of `group_id` this device holds: an active
    /// copy past `head_epoch` that the group's own head vouched for at an
    /// epoch above `head_epoch` (a head read under the group's handle that
    /// named the copy's verifier there, a Welcome seated at such a head, or a
    /// merge of this device's own commit, which that handle took), AND that
    /// held `head_epoch` itself under the send key `head_verifier` names
    /// when `head_epoch` is one of the epochs it still keeps a verifier for
    /// (its last [`COPY_VERIFIERS_KEPT`](crate::storage::COPY_VERIFIERS_KEPT)).
    /// A head below every kept epoch has nothing to be held against, and a
    /// steward's veto can name one there, so it needs only the vouching on a
    /// copy that has kept a whole window since its seat, in a group no
    /// steward was ever named or stamped for on this copy
    /// ([`Self::steward_ever_named`]): there the group's head stood above it,
    /// so it moved back, however far. Anywhere else such a head reads
    /// forked: below a seat the copy still keeps, or wherever a veto could
    /// have moved the head onto a branch the copy never walked.
    ///
    /// Such a head is no fork. The group's own head stood above it on this
    /// copy's branch, so the server held the group past `head_epoch` and
    /// moved its head back. Within the kept epochs the verifier must be the
    /// copy's own, so a veto's replacement there still reads forked. A
    /// commit merely PLACED for this device vouches for nothing: anybody in
    /// the group can open another handle under the epoch's verifier, have a
    /// commit there placed for the members, and leave the group's head where
    /// it was; the copies that merged it are on a branch of their own, and
    /// read as forked, as before. The caller
    /// keeps its copy and its state: it neither forgets the group nor asks
    /// back in onto the older head, and a Welcome at or below the copy is
    /// refused anyway ([`Self::join_from_welcome_at_head`]: a live copy
    /// never moves back). Its own commits are refused until the head comes
    /// back up; its messages still go, addressed to devices, not to the head.
    ///
    /// False for a head at or above the copy, a group not held or not
    /// active, a head the group's own head never stood above on this copy,
    /// a verifier of any length but 32, within the kept epochs one that is
    /// not the copy's own at that epoch, and below them one on a copy with
    /// fewer than a window's epochs kept or in a group a steward was named
    /// for: a head the copy never passed through is judged as a fork, as
    /// before (docs/delivery.md §A commit the server refuses).
    /// Reads only.
    pub fn head_rolled_back(
        &self,
        group_id: &[u8],
        head_epoch: u64,
        head_verifier: &[u8],
    ) -> Result<bool> {
        let Some(group) = self.groups.get(group_id) else {
            return Ok(false);
        };
        if !group.is_active() || head_epoch >= group.epoch().as_u64() || head_verifier.len() != 32 {
            return Ok(false);
        }
        let storage = self.provider.peachy_storage();
        // The group's own head stood above `head_epoch` on this copy.
        if !storage
            .head_vouched(group_id)?
            .is_some_and(|vouched| vouched > head_epoch)
        {
            return Ok(false);
        }
        let kept = storage.copy_verifiers(group_id)?;
        let passed = match kept.first() {
            // Within the kept epochs: the copy's own verifier there, or a
            // branch it never walked.
            Some((oldest, _)) if head_epoch >= *oldest => kept.iter().any(|(epoch, verifier)| {
                *epoch == head_epoch && verifier.as_slice() == head_verifier
            }),
            // Below all of them there is nothing to hold it against, and a
            // veto can name an epoch there: one more than 63 epochs back, or
            // one before the copy was seated, on a branch the copy never
            // walked. So the vouching alone says the head moved back only on
            // a copy that has walked a whole window of epochs since its seat,
            // so that the seat has left the window (a shorter one keeps its
            // seat, and a head below the seat holds no leaf of this copy
            // anyway), in a group this copy has POSITIVE
            // evidence no steward exists for: it opened at least one stamp
            // since its seat, every one it opened named no steward key, and
            // nothing else it holds names one ([`Self::steward_ever_named`]).
            // A copy that opened no stamp (one making only its own commits
            // since its seat) knows nothing of the server's key, and a
            // missing record is no evidence. Anything else reads forked, and
            // the copy rejoins.
            _ => {
                storage.copy_walked_past_seat(group_id)?
                    && storage.stamps_named_steward(group_id)? == Some(false)
                    && !self.steward_ever_named(group_id, group)?
            }
        };
        if passed {
            log::warn!(
                "peachy-mls: a head at epoch {head_epoch}, below this copy's {}, is one the \
                 group's head stood above; the copy is kept",
                group.epoch().as_u64()
            );
        }
        Ok(passed)
    }

    /// When this device last finished reading `group_id`'s head, in unix
    /// milliseconds, as [`Self::note_head_read`] recorded it; `None` when it
    /// never did for this copy, or the group is not held. Opening the
    /// conversation reads the head again when this is a week old
    /// (docs/delivery.md §A commit the server refuses). Kept in the
    /// group's own records, in this store, and dropped with the group.
    /// Reads only.
    pub fn last_head_read(&self, group_id: &[u8]) -> Result<Option<i64>> {
        if !self.groups.contains_key(group_id) {
            return Ok(None);
        }
        Ok(self.provider.peachy_storage().head_read_at(group_id)?)
    }

    /// Record that a read of `group_id`'s head finished at `at_ms` (unix
    /// milliseconds), whatever it answered. Refused for a group not held.
    /// Under the store's write lock.
    pub fn note_head_read(&mut self, group_id: &[u8], at_ms: i64) -> Result<()> {
        self.synced(|client| {
            if !client.groups.contains_key(group_id) {
                return Err(Error::NoSuchGroup);
            }
            client
                .provider
                .peachy_storage()
                .set_head_read_at(group_id, at_ms)?;
            Ok(())
        })
    }

    /// The SHA-256 of the send key of the active copy of `group_id` held
    /// now, at its current epoch: what a head names it by.
    pub(crate) fn verifier_of_held(&self, group_id: &[u8]) -> Result<Option<[u8; 32]>> {
        let Some(held) = self.groups.get(group_id) else {
            return Ok(None);
        };
        if !held.is_active() {
            return Ok(None);
        }
        let secret = Zeroizing::new(
            held.export_secret(self.provider.crypto(), SEND_KEY_LABEL, group_id, 32)
                .map_err(mls_err)?,
        );
        Ok(Some(sha2::Sha256::digest(&secret[..]).into()))
    }

    /// The steward key `group` (the copy of `group_id`) is ENROLLED under, if
    /// any. Its meta's `stw.k` alone does not do it, because under
    /// `pol.meta: "any"` any member may write `stw`. The group is enrolled
    /// only while the key it COUNTS ([`Self::counted_steward_key`]) is the
    /// steward key the server's sealed stamp named on the last commit this
    /// device merged, or on a commit at its epoch it refused
    /// (`NS_STAMP_STEWARD` in crate::storage), which the server sets only at
    /// CreateHandle and changes only under the old key's signature. A meta
    /// key with no matching stamp is ignored, not refused: the group behaves
    /// as one never enrolled. A copy seated by a Welcome counts from the
    /// first stamped commit it opens; a founder and a rotator from their own
    /// commit ([`StewardMerge::own`]).
    fn enrolled_steward_key(&self, group_id: &[u8], group: &MlsGroup) -> Result<Option<[u8; 32]>> {
        let Some(counted) = self.counted_steward_key(group_id, group)? else {
            return Ok(None);
        };
        let stamped = self.provider.peachy_storage().stamp_steward(group_id)?;
        Ok((stamped == Some(counted)).then_some(counted))
    }

    /// Whether anything this copy of `group_id` holds names a steward,
    /// beside the stamps it opened (`stamps_named_steward`, which
    /// [`Self::head_rolled_back`] reads as well): the group counts a steward
    /// key, or the copy still keeps the key it had at some epoch (kept for a
    /// veto of that epoch's commit; the one record left once an admin's own
    /// commit removes `stw`, since no stamp of an own commit comes back).
    /// Wider than [`Self::enrolled_steward_key`] on purpose: a copy seated
    /// by a Welcome is not enrolled until a stamped commit, but a veto can
    /// still undo the branch it was seated on, so [`Self::head_rolled_back`]
    /// fails closed on either.
    fn steward_ever_named(&self, group_id: &[u8], group: &MlsGroup) -> Result<bool> {
        let storage = self.provider.peachy_storage();
        Ok(self.counted_steward_key(group_id, group)?.is_some()
            || !storage.steward_keys(group_id)?.is_empty())
    }

    /// The steward key `group` counts for enrollment: its meta's `stw.k`,
    /// unless a commit by somebody who may not change it
    /// (`crate::steward::may_change_steward_key`) rewrote that, in which case
    /// the key as it stood before (`NS_COUNTED_STEWARD` in crate::storage).
    /// So a plain member who rewrites or deletes `stw.k` neither enrolls nor
    /// un-enrolls the group on this device.
    fn counted_steward_key(&self, group_id: &[u8], group: &MlsGroup) -> Result<Option<[u8; 32]>> {
        if let Some(counted) = self.provider.peachy_storage().counted_steward(group_id)? {
            return Ok(counted);
        }
        Ok(group_meta_from_context(group.extensions())
            .and_then(|meta| crate::steward::steward_key_of_meta(&meta)))
    }

    /// What a commit by `actor` (as the policy names it: empty for nobody)
    /// is about to do to the counted steward key of the copy of `group_id`,
    /// read before the merge ([`StewardMerge`]).
    fn steward_merge_of(
        &self,
        group_id: &[u8],
        actor: &str,
        own: bool,
    ) -> Result<Option<StewardMerge>> {
        let Some(group) = self.groups.get(group_id) else {
            return Ok(None);
        };
        let prior = group_meta_from_context(group.extensions());
        Ok(Some(StewardMerge {
            named_before: prior
                .as_deref()
                .and_then(crate::steward::steward_key_of_meta),
            counted_before: self.counted_steward_key(group_id, group)?,
            may_change: crate::steward::may_change_steward_key(prior.as_deref(), actor),
            own,
        }))
    }

    /// Record `key`, named by the stamp of a commit at this copy's epoch the
    /// door refused, as stamped, when it is the key the group counts here.
    /// Best effort: the refusal stands whatever the store says.
    fn keep_refused_stamp(&mut self, group_id: &[u8], key: &[u8; 32]) {
        let Some(group) = self.groups.get(group_id) else {
            return;
        };
        if !group.is_active() {
            return;
        }
        match self.counted_steward_key(group_id, group) {
            Ok(Some(counted)) if &counted == key => {}
            Ok(_) => return,
            Err(err) => {
                log::warn!("peachy-mls: could not read the counted steward key: {err}");
                return;
            }
        }
        let epoch = group.epoch().as_u64();
        let now = self.identity_provider.now_unix();
        let storage = self.provider.peachy_storage();
        let kept = storage
            .set_stamp_steward(group_id, Some(key))
            .and_then(|()| storage.note_steward_key(group_id, epoch, now, key));
        if let Err(err) = kept {
            log::warn!("peachy-mls: could not keep a refused commit's stamp: {err}");
        }
    }

    /// Record the epoch the copy of `group_id` is at now, by the verifier a
    /// head would name it by, for [`Self::confirm_head`] to judge a trailing
    /// head against. Called at every epoch the copy enters: a seat, a group
    /// founded, a commit merged. When the copy was seated below a head and
    /// has now reached that head's epoch, it is held to it: the same
    /// verifier confirms the copy, another contests it.
    fn note_copy_epoch(&mut self, group_id: &[u8]) -> Result<()> {
        self.reopen_anew();
        self.note_envelope_epoch(group_id, None)?;
        self.note_leaf_people(group_id)?;
        let Some(group) = self.groups.get(group_id) else {
            return Ok(());
        };
        let epoch = group.epoch().as_u64();
        let Some(verifier) = self.verifier_of_held(group_id)? else {
            return Ok(());
        };
        let storage = self.provider.peachy_storage();
        storage.note_copy_verifier(group_id, epoch, &verifier)?;
        // The steward key the stamp of the commit that brought the copy here
        // named, when one came with it: inside the merge's own write, so the
        // record and the epoch it describes land together.
        if let Some(stamped) = self.stamp_stewards.get(group_id) {
            storage.set_stamp_steward(group_id, stamped.as_ref())?;
            storage.note_stamp_opened(group_id, stamped.is_some())?;
        }
        // What the merge did to the key the group counts: a change to `stw.k`
        // by somebody who may not make one leaves the key as it stood; one by
        // somebody who may drops that record, so the meta counts; and this
        // device's own such commit is the server's key too (`StewardMerge`).
        let merge = self.steward_merges.remove(group_id);
        if let Some(merge) = &merge {
            let named_now = group_meta_from_context(group.extensions())
                .and_then(|meta| crate::steward::steward_key_of_meta(&meta));
            if named_now != merge.named_before {
                if merge.may_change {
                    storage.set_counted_steward(group_id, None)?;
                    if merge.own {
                        storage.set_stamp_steward(group_id, named_now.as_ref())?;
                    }
                } else if storage.counted_steward(group_id)?.is_none() {
                    log::warn!(
                        "peachy-mls: a commit by a member who may not change the steward key \
                         rewrote it; it does not count"
                    );
                    storage.set_counted_steward(group_id, Some(merge.named_before.as_ref()))?;
                }
            }
        }
        // The steward key at this epoch, for judging a veto of the commit
        // that leaves it (crate::steward): only a key the group is enrolled
        // under, which a member writing `stw` cannot make. Nothing for a
        // group never enrolled.
        if let Some(key) = self.enrolled_steward_key(group_id, group)? {
            let now = self.identity_provider.now_unix();
            storage.note_steward_key(group_id, epoch, now, &key)?;
            // And at the epoch the merge left, when this device kept none
            // there (a copy seated by a Welcome, enrolled only by this
            // commit's stamp): the stamp names the key the handle holds from
            // the commit on, which was the key at the epoch before as well
            // when the commit changed nothing the group counts.
            let stamped_now = self.stamp_stewards.get(group_id).copied().flatten();
            if let (Some(merge), Some(stamped), Some(left)) =
                (&merge, stamped_now, epoch.checked_sub(1))
            {
                let kept_there = storage
                    .steward_keys(group_id)?
                    .iter()
                    .any(|(at, _, _)| *at == left);
                if stamped == key && merge.counted_before == Some(key) && !kept_there {
                    storage.note_steward_key(group_id, left, now, &key)?;
                }
            }
        }
        let Some((join_epoch, join_verifier)) = storage.join_head(group_id)? else {
            return Ok(());
        };
        if join_epoch > epoch {
            return Ok(());
        }
        if storage.head_state(group_id)? != HeadState::Unconfirmed {
            return Ok(storage.forget_join_head(group_id)?);
        }
        let held = storage
            .copy_verifiers(group_id)?
            .into_iter()
            .find(|(at, _)| *at == join_epoch);
        match held {
            Some((_, held)) if held == join_verifier => {
                storage.vouch_head_epoch(group_id, join_epoch)?;
                self.note_head_confirmed(group_id)
            }
            Some(_) => self.contest_copy(group_id),
            // An epoch the copy skipped: nothing to hold it to.
            None => Ok(storage.forget_join_head(group_id)?),
        }
    }

    /// A head contradicted the copy of `group_id` before any head matched
    /// it: mark it [`HeadState::Contested`] and keep a report saying so
    /// ([`RejoinReport::contested`]), once. The copy stays unvouched, so a
    /// Welcome into the real group can still replace it.
    fn contest_copy(&self, group_id: &[u8]) -> Result<()> {
        let storage = self.provider.peachy_storage();
        storage.forget_join_head(group_id)?;
        if storage.head_state(group_id)? != HeadState::Unconfirmed {
            return Ok(());
        }
        log::warn!(
            "peachy-mls: the group's head contradicts a copy no head has matched yet — the copy \
             is contested"
        );
        storage.set_head_state(group_id, HeadState::Contested)?;
        self.keep_rejoin_report(
            group_id,
            RejoinReport {
                contested: true,
                ..RejoinReport::default()
            },
        )
    }

    /// Whether this device holds an active copy of `group_id` at
    /// `head_epoch` whose send key hashes to `head_verifier`.
    fn held_at_head(&self, group_id: &[u8], head_epoch: u64, head_verifier: &[u8]) -> Result<bool> {
        let Some(held) = self.groups.get(group_id) else {
            return Ok(false);
        };
        if !held.is_active() || held.epoch().as_u64() != head_epoch {
            return Ok(false);
        }
        let secret = Zeroizing::new(
            held.export_secret(self.provider.crypto(), SEND_KEY_LABEL, group_id, 32)
                .map_err(mls_err)?,
        );
        let verifier: [u8; 32] = sha2::Sha256::digest(&secret[..]).into();
        Ok(verifier.as_slice() == head_verifier)
    }

    /// Record that the copy of `group_id` held now is the group's head
    /// ([`Self::confirm_head`]): the flag, the epoch mark at its epoch, and
    /// the roster, group state and join head kept for it spent.
    fn note_head_confirmed(&self, group_id: &[u8]) -> Result<()> {
        let Some(group) = self.groups.get(group_id) else {
            return Ok(());
        };
        let storage = self.provider.peachy_storage();
        if !storage.head_confirmed(group_id)? {
            storage.set_head_state(group_id, HeadState::Confirmed)?;
            storage.forget_remembered_roster(group_id)?;
            storage.forget_join_head(group_id)?;
        }
        storage.raise_epoch_mark(group_id, group.epoch().as_u64())?;
        Ok(())
    }

    /// Spend the key package of the Welcome a refused frame holds
    /// ([`crate::welcome_frame::welcome_in_refused_frame`]): a raw Welcome
    /// sent without its frame, or one in a frame whose fill or gap block is
    /// wrong. The frame is refused either way; spending the package first is
    /// what every other refused Welcome does, so its private keys do not stay
    /// at rest for a Welcome that seats this device in everyone else's tree.
    /// Bytes that are not a Welcome, or are sealed to no package this device
    /// holds, spend nothing; a last-resort package is kept, as on any join.
    /// Only a storage failure is an error.
    fn spend_refused_frame(&self, bytes: &[u8]) -> Result<()> {
        let inner = crate::welcome_frame::welcome_in_refused_frame(bytes);
        let Ok(message) = MlsMessageIn::tls_deserialize_exact(inner) else {
            return Ok(());
        };
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Ok(());
        };
        match StagedWelcome::build_from_welcome(&self.provider, &Self::join_config(), welcome) {
            Err(err @ WelcomeError::StorageError(_)) => Err(mls_err(err)),
            _ => Ok(()),
        }
    }

    fn join_from_welcome_inner(
        &mut self,
        welcome: &[u8],
        head: Option<(u64, &[u8])>,
        logged: Option<LogAnswer<'_>>,
    ) -> Result<Vec<u8>> {
        self.contested_welcome = None;
        // A padded frame, never a raw Welcome (crate::welcome_frame), and
        // the gap block a reseat's frame carries. A refused frame still
        // spends the key package its Welcome is sealed to.
        let parts = match crate::welcome_frame::unframe_welcome_parts(welcome) {
            Ok(parts) => parts,
            Err(err) => {
                self.spend_refused_frame(welcome)?;
                return Err(err);
            }
        };
        let welcome = parts.welcome;
        let gap_block = parts.gap_block.map(<[u8]>::to_vec);
        // A WELCOME ALREADY TAKEN THROUGH A LAST-RESORT PACKAGE, as a store
        // holds it by the digest of the whole Welcome, is
        // refused before anything opens it. This build records the seat the
        // Welcome opens to instead, checked below once it is open.
        let welcome_digest: [u8; 32] = sha2::Sha256::digest(welcome).into();
        if self
            .provider
            .peachy_storage()
            .welcome_taken(&welcome_digest)?
        {
            log::warn!("peachy-mls: refused a Welcome this device already took");
            return Err(Error::AlreadyAMember);
        }
        let message = MlsMessageIn::tls_deserialize_exact(welcome)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(Error::invalid("that message is not a Welcome"));
        };
        // Which packages the Welcome is sealed to, read before the builder
        // takes it: a seat opened with a LAST-RESORT package of this device's
        // is not a fresh leaf (at the end).
        let sealed_to: Vec<Vec<u8>> = welcome
            .secrets()
            .iter()
            .map(|secret| secret.new_member().as_slice().to_vec())
            .collect();

        // Processed first, staged second, so the group id is known BEFORE the
        // question "is this a group we already hold?" has to be answered. It
        // is the Welcome's UNVERIFIED id — good enough to decide whether to
        // stage with a replacement, and re-read from the verified context
        // below before anything is kept.
        let kept = (!self.leaving.is_empty()).then(|| welcome.clone());
        let mut builder =
            StagedWelcome::build_from_welcome(&self.provider, &Self::join_config(), welcome)
                .map_err(mls_err)?;
        let mut claimed = builder
            .processed_welcome()
            .unverified_group_info()
            .group_id()
            .as_slice()
            .to_vec();
        // A WELCOME INTO A GROUP THIS DEVICE IS LEAVING: somebody seated it
        // again, so the leave is over. Opening the Welcome spent its key
        // package, which the rollback puts back (nothing else is written yet
        // in this door); the stub goes as a finished leave does, and the
        // Welcome, opened again over no state, is judged as one into a group
        // this device left.
        if let Some(welcome) = kept.filter(|_| self.leaving.contains_key(&claimed)) {
            drop(builder);
            self.provider.peachy_storage().rollback()?;
            self.provider.peachy_storage().begin_write()?;
            if let Some(stub) = self.leaving.remove(&claimed) {
                self.groups.insert(claimed.clone(), stub);
                self.finish_leave(&claimed)?;
            }
            builder =
                StagedWelcome::build_from_welcome(&self.provider, &Self::join_config(), welcome)
                    .map_err(mls_err)?;
            claimed = builder
                .processed_welcome()
                .unverified_group_info()
                .group_id()
                .as_slice()
                .to_vec();
        }
        // A saved commit is settled before a Welcome against the head may
        // replace the group; the door puts the key package back.
        if head.is_some() {
            self.refuse_unsettled(&claimed)?;
        }
        // A HELD GROUP THAT IS NO LONGER ACTIVE IS NOT A GROUP WE ARE IN. The
        // commit that removed this device left its state behind, inactive —
        // and refusing a re-add's Welcome over that state would answer
        // `AlreadyAMember` with the Welcome consumed by the fetch and the
        // key package spent, so the member re-seated by somebody else's next
        // reconcile could never take the seat: the Welcome goes unused and
        // the device says `notAMember` on every open after. An
        // ACTIVE group still refuses, for every reason the doc above gives —
        // but its Welcome is staged and kept, in memory, for the one question
        // that can still overturn the refusal: which of the two is the group
        // the delivery service holds ([`Self::join_contested_welcome`]).
        let held_active = self
            .groups
            .get(&claimed)
            .is_some_and(|held| held.is_active());
        let replacing = self.groups.contains_key(&claimed);
        let builder = if replacing {
            builder.replace_old_group()
        } else {
            builder
        };
        // NO LIFETIME VERDICT ON THE TREE'S LEAVES, on this joiner's clock: a
        // leaf its member never renewed keeps the window its package was
        // minted with, and judging that on the joiner's wall made every
        // Welcome into the group fail once it lapsed. Its adder judged it
        // (crate::key_package_lifetime); the credential checks below still
        // judge every leaf. (`peek_welcome` builds nothing, so it judges no
        // lifetime either.)
        let builder = builder.skip_lifetime_validation();
        // None for the tree: it rides in the Welcome. An out-of-band tree is
        // the other half of this API and belongs with the delivery service.
        let staged = match builder.build() {
            Ok(staged) => staged,
            Err(WelcomeError::GroupAlreadyExists) => return Err(Error::AlreadyAMember),
            Err(_) if held_active => return Err(Error::AlreadyAMember),
            Err(err) => return Err(mls_err(err)),
        };

        // Checked BEFORE the members are validated and before `into_group`, so
        // the live group survives a duplicate Welcome whatever else is wrong
        // with it — against the VERIFIED id now, which must be the one the
        // decision above was made about.
        let group_id = staged.group_context().group_id().as_slice().to_vec();
        if group_id != claimed {
            return Err(Error::invalid(
                "the Welcome's group id changed under verification",
            ));
        }
        if !replacing && self.groups.contains_key(&group_id) {
            return Err(Error::AlreadyAMember);
        }
        let welcome_epoch = staged.group_context().epoch().as_u64();
        // A SEAT ALREADY TAKEN THROUGH A LAST-RESORT PACKAGE is refused. That
        // package's private half outlives the seat by design, so the delivery
        // service, which keeps every Welcome it relayed, could otherwise hand
        // it back and seat this device again at the epoch it sealed. Keyed by
        // what the Welcome opened to, which nobody can change and still have
        // it open: its `secrets` list is not signed, so a key over the whole
        // Welcome was one the delivery service could move.
        let taken_key = crate::storage::welcome_taken_key(
            &group_id,
            welcome_epoch,
            staged.group_context().confirmed_transcript_hash(),
        );
        if self.provider.peachy_storage().welcome_taken(&taken_key)? {
            log::warn!("peachy-mls: refused a Welcome this device already took");
            return Err(Error::AlreadyAMember);
        }
        // THE HEAD CAPS THE SEAT. A Welcome of a real add is placed in the
        // step that moves the head to its epoch, so one above the head, or at
        // it under another send key, seats this device in no group the
        // delivery service holds.
        let at_head = match head {
            None => false,
            Some((head_epoch, head_verifier)) => {
                if welcome_epoch > head_epoch {
                    log::warn!("peachy-mls: refused a Welcome above the group's head");
                    return Err(Error::AlreadyAMember);
                }
                if welcome_epoch == head_epoch {
                    let secret = Zeroizing::new(
                        staged
                            .export_secret(self.provider.crypto(), SEND_KEY_LABEL, &group_id, 32)
                            .map_err(mls_err)?,
                    );
                    let verifier: [u8; 32] = sha2::Sha256::digest(&secret[..]).into();
                    if verifier.as_slice() != head_verifier {
                        log::warn!(
                            "peachy-mls: refused a Welcome at the group's head epoch under \
                             another send key"
                        );
                        return Err(Error::AlreadyAMember);
                    }
                }
                welcome_epoch == head_epoch
            }
        };
        // THE VERIFIER LOG PLACES A WELCOME BELOW THE HEAD. The server logs
        // the verifier of every epoch a head passes through, so a Welcome at
        // an epoch the log names is a seat in the group the server holds only
        // when its send key hashes to what the log holds there.
        let logged_match = match (head, logged) {
            (Some((head_epoch, _)), Some(answer)) if welcome_epoch < head_epoch => {
                match answer.verifier {
                    Some(logged) => {
                        let secret = Zeroizing::new(
                            staged
                                .export_secret(
                                    self.provider.crypto(),
                                    SEND_KEY_LABEL,
                                    &group_id,
                                    32,
                                )
                                .map_err(mls_err)?,
                        );
                        let verifier: [u8; 32] = sha2::Sha256::digest(&secret[..]).into();
                        if verifier.as_slice() != logged {
                            log::warn!(
                                "peachy-mls: refused a Welcome below the group's head whose send \
                                 key is not the one the verifier log holds at its epoch"
                            );
                            return Err(Error::AlreadyAMember);
                        }
                        true
                    }
                    // THE LOG HOLDS EVERY EPOCH FROM ITS FLOOR, so an epoch at
                    // or above it with no row is one the real group never
                    // passed through.
                    None if answer.kept_from.is_some_and(|floor| welcome_epoch >= floor) => {
                        log::warn!(
                            "peachy-mls: refused a Welcome below the group's head at an epoch the \
                             verifier log keeps and holds nothing for"
                        );
                        return Err(Error::AlreadyAMember);
                    }
                    None => {
                        log::warn!(
                            "peachy-mls: a Welcome below the group's head at an epoch the \
                             verifier log does not keep; judged without it"
                        );
                        false
                    }
                }
            }
            _ => false,
        };
        // A seat the server's word places in its group: at the head, or at an
        // epoch the verifier log vouches for.
        let placed = at_head || logged_match;
        // A GROUP ONLY MOVES FORWARD ON THIS DEVICE. A Welcome at or below
        // the epoch mark is refused, held, removed from or forgotten alike,
        // whatever head is given: it is a past state of the group (a Welcome
        // replayed), or a branch beside one, and taking it would roll this
        // device's keys back to a tree that may still hold a member removed
        // since. The mark counts only epochs the head vouched for
        // ([`Self::epoch_mark`]).
        self.refuse_stale_welcome(&group_id, welcome_epoch)?;

        // Every SEATED member is checked with the same expired-leaf grace the
        // members already in the group extend to each other
        // (crate::identity::EXPIRED_LEAF_GRACE_SECONDS). Strictly, one member
        // whose leaf had lapsed — somebody on a build that never renews, or a
        // phone in a drawer — made the whole group unjoinable, including for
        // the device a rejoin exists to bring back. The Welcome's signer is
        // read with the same grace (just below); the key package it was
        // sealed to is this device's own, checked strictly by the committer
        // at the Add.
        //
        // THIS IS THE ONE CREDENTIAL VERDICT ON GROUP STATE STILL MADE ON THE
        // READER'S WALL, and it is a known, accepted gap rather than an
        // oversight. Every other one is on the
        // tree clock. A joiner who reads its Welcome more than 56 days after
        // some seated leaf's `exp` refuses the whole Welcome — but it refuses
        // only itself: it holds no state for the group, so nobody forks, and
        // the leaf that caused it reads as unidentified in every member's
        // roster and is evicted by the next member device that sends into the
        // group or passes over it in the foreground, after which the joiner can
        // be added again. docs/identity.md §The joiner reads its
        // Welcome on its own wall.
        for member in staged.members() {
            let checked = self.identity_provider.validate_seated_credential(
                &member.credential,
                &member.signature_key,
                crate::identity::EXPIRED_LEAF_GRACE_SECONDS,
            );
            match checked {
                Ok(_) => {}
                // A duplicate stays a duplicate whatever else is wrong with it.
                Err(_) if held_active => return Err(Error::AlreadyAMember),
                Err(err) => return Err(err),
            }
        }
        // ONE PERSON, ONE ACCOUNT KEY (`crate::policy::judge_account_keys`),
        // as every commit is judged (`refuse_account_key_conflict`). Every
        // leaf of a Welcome is new to its reader, so all are judged as added: a tree holding one person under
        // two account keys, or this device's own person under a key that is
        // not theirs, is one no honest member's commit could have made.
        let seats: Vec<crate::policy::Seat> = staged
            .members()
            .filter_map(|member| {
                self.identity_provider
                    .validate_seated_credential(&member.credential, &member.signature_key, i64::MAX)
                    .ok()
            })
            .map(|(identity, _)| Self::seat_of(identity))
            .collect();
        let reader = self
            .identity
            .account_key
            .as_ref()
            .map(|key| (self.identity.actor_id.as_str(), key));
        if let PolicyDecision::Deny(reason) = crate::policy::judge_account_keys(reader, &[], &seats)
        {
            return Err(Error::PolicyRefused(reason));
        }
        // WHO SEATED THIS DEVICE: the GroupInfo's signer, the member whose
        // commit added it ([`Self::welcome_sender`]). Its credential was just
        // validated with the rest of the tree.
        let sender_index = staged.welcome_sender_index();
        let sender_identity = staged
            .members()
            .find(|m| m.index == sender_index)
            .and_then(|m| {
                self.identity_provider
                    .validate_seated_credential(
                        &m.credential,
                        &m.signature_key,
                        crate::identity::EXPIRED_LEAF_GRACE_SECONDS,
                    )
                    .ok()
            })
            .map(|(identity, _lapsed)| identity);
        let welcome_sender_key = sender_identity.as_ref().and_then(|id| id.account_key);
        let welcome_sender_device = sender_identity
            .as_ref()
            .map(|id| (id.device_id.clone(), id.device_key));
        let welcome_sender = sender_identity.map(|identity| identity.actor_id);

        let seat = StagedSeat {
            group_id,
            staged,
            sealed_to,
            welcome_sender,
            welcome_sender_key,
            welcome_sender_device,
            taken_key,
            gap_block,
        };
        if held_active {
            let Some((head_epoch, head_verifier)) = head else {
                self.contested_welcome = Some(seat);
                return Err(Error::AlreadyAMember);
            };
            // Against the head: the held copy goes only for a Welcome AT the
            // head (or one the verifier log places), and only when the copy
            // is not at the head itself.
            if !placed || self.held_at_head(&seat.group_id, head_epoch, head_verifier)? {
                return Err(Error::AlreadyAMember);
            }
            // A WELCOME THE LOG PLACES BELOW THE HEAD never moves a live copy
            // back, vouched or not: a real Welcome withheld and handed over
            // late would put this device on a tree that may still hold a
            // member removed since.
            if logged_match && !at_head {
                let held_epoch = self
                    .groups
                    .get(&seat.group_id)
                    .map_or(0, |held| held.epoch().as_u64());
                if held_epoch >= welcome_epoch {
                    log::warn!(
                        "peachy-mls: refused a logged Welcome below the group's head that would \
                         move the copy held back"
                    );
                    return Err(Error::AlreadyAMember);
                }
            }
            self.refuse_active_rollback(&seat)?;
            let judged = self.judge_replacing_welcome(&seat)?;
            log::warn!(
                "peachy-mls: a Welcome matched the group's head and the group this device held \
                 did not — replacing the held group"
            );
            return self.take_seat(seat, judged, true, true, None);
        }
        // A WELCOME INTO A GROUP THIS DEVICE KNEW (the inactive copy it holds
        // after a removal its own person survived, or the roster it kept when
        // it forgot the group) is drawn against it. A Welcome from a device
        // this account forgot is refused into any group, with the key package
        // spent as on any refusal.
        let mut judged = self.judge_replacing_welcome(&seat)?;
        // DEVICES LEFT OUT ARE NAMED ONLY FOR A SEAT THE SERVER'S WORD
        // PLACES: one taken unconfirmed may be in a group somebody founded
        // under the id, and the own-seat pass would add this person's other
        // devices to it.
        if !placed {
            if let Some(judged) = judged.as_mut() {
                judged.dropped_devices.clear();
            }
        }
        // A seat below the head keeps the head it was taken against: the copy
        // is held to it once it gets there ([`Self::note_copy_epoch`]).
        let join_head = match head {
            Some((epoch, verifier)) if !placed => <[u8; 32]>::try_from(verifier)
                .ok()
                .map(|verifier| (epoch, verifier)),
            _ => None,
        };
        self.take_seat(seat, judged, head.is_some(), placed, join_head)
    }

    /// The group id of the Welcome the last [`Self::join_from_welcome`]
    /// refused as [`Error::AlreadyAMember`], while it is still kept; `None`
    /// once it is decided, replaced by the next join, or for a refusal of any
    /// other kind. In memory only: a restart forgets it.
    pub fn contested_welcome_group_id(&self) -> Option<Vec<u8>> {
        self.contested_welcome
            .as_ref()
            .map(|seat| seat.group_id.clone())
    }

    /// Settle the Welcome [`Self::join_from_welcome`] refused because this
    /// device already holds an active group with its id, by the group's head
    /// as the delivery service reports it (`FetchConversationHead` for
    /// [`crate::envelope::group_handle`] of that id): its epoch and the
    /// SHA-256 of that epoch's send key.
    ///
    /// Why it exists: a group id is a name, not a secret from everybody. A
    /// removed member keeps it, and can found a group of its own under it and
    /// seat a device that does not hold the group yet with a Welcome to that,
    /// so the real group's Welcome then finds an active copy. The server
    /// cannot read a Welcome, so it cannot tell the two apart when it
    /// delivers them; the head is what it does know. The apps take every
    /// Welcome through [`Self::join_from_welcome_at_head`], which settles the
    /// same question in one call.
    ///
    /// - The held group IS the head (same epoch, same send key): it stays,
    ///   and this answers [`Error::AlreadyAMember`] as before.
    /// - Otherwise, the Welcome's group is the head: the held group is
    ///   deleted, all of it, and the device takes the Welcome's seat.
    ///   Answers the group id.
    /// - Neither: [`Error::AlreadyAMember`]. A held group the head does not
    ///   match is the fork check's to judge, by the same head, later.
    ///
    /// The Welcome is spent either way. [`Error::InvalidArgument`] when no
    /// Welcome is waiting.
    ///
    /// **The head breaks a tie, and the replacement is drawn.** The head is
    /// the delivery service's word, and anybody who knows the id can found a
    /// group under it and hand the server that group's epoch and verifier.
    /// So a Welcome the head prefers leaves a report of what it changes
    /// against the held group's people ([`Self::judge_replacing_welcome`]):
    /// who re-added this device, who was added, who is gone, whether the
    /// admins changed. Only a Welcome signed by a device this account forgot
    /// is refused. A held group that names nobody but this device's own
    /// person is drawn too: whoever the Welcome brings is drawn as added.
    ///
    /// **Nor does the head ever move a group back.** A Welcome at or below
    /// the group's epoch mark ([`Self::epoch_mark`]) is refused with
    /// [`Error::AlreadyAMember`] first, whatever head is passed: a server
    /// that kept an old Welcome kept that epoch's head as well. One at or
    /// below the epoch of an active copy a head once vouched for (confirmed
    /// or lapsed) is refused the same way. A copy no head vouched for may be
    /// replaced at any epoch.
    ///
    /// Flushed on every outcome, as [`Self::join_from_welcome`] is.
    pub fn join_contested_welcome(
        &mut self,
        head_epoch: u64,
        head_verifier: &[u8],
    ) -> Result<Vec<u8>> {
        self.synced(|client| {
            let outcome = client.join_contested_welcome_inner(head_epoch, head_verifier);
            client.flushed_and_erased(())?;
            outcome
        })
    }

    fn join_contested_welcome_inner(
        &mut self,
        head_epoch: u64,
        head_verifier: &[u8],
    ) -> Result<Vec<u8>> {
        // Refused BEFORE the Welcome is taken: it stays kept, for the same
        // call once the saved commit is settled.
        if let Some(seat) = &self.contested_welcome {
            self.refuse_unsettled(&seat.group_id)?;
        }
        let seat = self
            .contested_welcome
            .take()
            .ok_or_else(|| Error::invalid("no refused Welcome is waiting on the group's head"))?;
        // Whatever the head says: the head is the server's word, and a server
        // that kept an old Welcome also kept the head of the epoch it sealed.
        // The held group may have moved on since the Welcome was kept, too.
        self.refuse_stale_welcome(&seat.group_id, seat.staged.group_context().epoch().as_u64())?;
        let crypto = self.provider.crypto();
        let verifier_of =
            |secret: Zeroizing<Vec<u8>>| -> [u8; 32] { sha2::Sha256::digest(&secret[..]).into() };
        if let Some(held) = self.groups.get(&seat.group_id) {
            if held.is_active() && held.epoch().as_u64() == head_epoch {
                let held_secret = Zeroizing::new(
                    held.export_secret(crypto, SEND_KEY_LABEL, &seat.group_id, 32)
                        .map_err(mls_err)?,
                );
                if verifier_of(held_secret).as_slice() == head_verifier {
                    return Err(Error::AlreadyAMember);
                }
            }
        }
        if seat.staged.group_context().epoch().as_u64() != head_epoch {
            return Err(Error::AlreadyAMember);
        }
        let staged_secret = Zeroizing::new(
            seat.staged
                .export_secret(crypto, SEND_KEY_LABEL, &seat.group_id, 32)
                .map_err(mls_err)?,
        );
        if verifier_of(staged_secret).as_slice() != head_verifier {
            return Err(Error::AlreadyAMember);
        }
        self.refuse_active_rollback(&seat)?;
        let known = self.judge_replacing_welcome(&seat)?;
        log::warn!(
            "peachy-mls: a Welcome matched the group's head and the group this device held did \
             not — replacing the held group"
        );
        self.take_seat(seat, known, true, true, None)
    }

    /// The highest epoch the group's head vouched for on this device: the
    /// mark it recorded (a seat taken against the head, a copy confirmed, a
    /// confirmed copy deleted), or the epoch of the copy it holds now when
    /// that copy is confirmed ([`Self::confirm_head`]), whichever is higher.
    /// A copy no head confirmed counts for nothing: its epochs are whatever
    /// the Welcome and the commits that built it said, and anybody who knows
    /// the group id can say any. `None` for a group it never held (or held
    /// only before the mark was kept).
    fn epoch_mark(&self, group_id: &[u8]) -> Result<Option<u64>> {
        let stored = self.provider.peachy_storage().epoch_mark(group_id)?;
        let held = match self.groups.get(group_id) {
            Some(group) if self.provider.peachy_storage().head_confirmed(group_id)? => {
                Some(group.epoch().as_u64())
            }
            _ => None,
        };
        Ok(stored.max(held))
    }

    /// Record the epoch of the copy of `group_id` this device holds, before
    /// that state is deleted or replaced, so the mark outlives it: when the
    /// copy is confirmed, and only then.
    fn raise_epoch_mark_to_held(&self, group_id: &[u8]) -> Result<()> {
        if let Some(group) = self.groups.get(group_id) {
            if self.provider.peachy_storage().head_confirmed(group_id)? {
                self.provider
                    .peachy_storage()
                    .raise_epoch_mark(group_id, group.epoch().as_u64())?;
            }
        }
        Ok(())
    }

    /// Whether the copy of `group_id` held now descends from one a head
    /// confirmed: it is confirmed, it was and lapsed, or it was held before
    /// this device kept the record. A seat taken below the head (or with
    /// none) that no head has matched yet is not, nor is one a head
    /// contradicted before any matched ([`HeadState::Contested`]). A later
    /// head never takes this away from a copy that has it
    /// ([`Self::confirm_head`]).
    fn held_copy_vouched(&self, group_id: &[u8]) -> Result<bool> {
        Ok(!matches!(
            self.provider.peachy_storage().head_state(group_id)?,
            HeadState::Unconfirmed | HeadState::Contested
        ))
    }

    /// The people of the copy of `group_id` held now ([`Self::claim_of_held`]),
    /// when it descends from one a head confirmed ([`Self::held_copy_vouched`]).
    /// A copy no head ever matched names whoever built it, so it is kept on
    /// forgetting for nobody, and the Welcome judge reads it only to report.
    fn vouched_claim_of_held(&self, group_id: &[u8]) -> Result<Option<Vec<RosterClaim>>> {
        let Some(group) = self.groups.get(group_id) else {
            return Ok(None);
        };
        if !self.held_copy_vouched(group_id)? {
            return Ok(None);
        }
        Ok(self.claim_of_held(group))
    }

    /// The people of the copy of `group_id` held now when no head ever
    /// matched it (a seat taken below a head the server named, or a group of
    /// somebody's own under the id), or the people kept when such a copy
    /// went: what the Welcome judge draws a replacement against too. Empty
    /// for any other copy.
    fn unvouched_held_roster(&self, group_id: &[u8]) -> Result<Vec<RosterClaim>> {
        let Some(group) = self.groups.get(group_id) else {
            // The report-only roster kept when such a copy was forgotten or
            // replaced ([`Self::remember_held_copy`]).
            return Ok(self
                .provider
                .peachy_storage()
                .remembered_unvouched(group_id)?);
        };
        if self.held_copy_vouched(group_id)? {
            return Ok(Vec::new());
        }
        Ok(self.claim_of_held(group).unwrap_or_default())
    }

    /// [`Error::AlreadyAMember`] for a Welcome that would replace an ACTIVE
    /// copy of its group at or below that copy's own epoch, whatever the head
    /// says, when the copy descends from one a head matched, confirmed now or
    /// lapsed since ([`Self::held_copy_vouched`]): a live group never moves
    /// back on this device. The copy may hold a removal the Welcome's tree
    /// predates; only a later epoch can be the group having moved on.
    ///
    /// A copy no head ever matched is the exception: its epochs are whatever
    /// the Welcome and commits that built it said, so a group of somebody's
    /// own under the id could otherwise wall the real group's Welcome out
    /// with an epoch it chose. Its replacement is judged and reported
    /// ([`Self::judge_replacing_welcome`]) instead.
    fn refuse_active_rollback(&self, seat: &StagedSeat) -> Result<()> {
        let Some(held) = self.groups.get(&seat.group_id) else {
            return Ok(());
        };
        if held.is_active()
            && seat.staged.group_context().epoch().as_u64() <= held.epoch().as_u64()
            && self.held_copy_vouched(&seat.group_id)?
        {
            log::warn!(
                "peachy-mls: refused a Welcome at or below the epoch of the live copy it would \
                 replace"
            );
            return Err(Error::AlreadyAMember);
        }
        Ok(())
    }

    /// [`Error::AlreadyAMember`] for a Welcome into `group_id` at `epoch` when
    /// this device already held the group at that epoch or later
    /// ([`Self::epoch_mark`]).
    fn refuse_stale_welcome(&self, group_id: &[u8], epoch: u64) -> Result<()> {
        if self.epoch_mark(group_id)?.is_some_and(|mark| epoch <= mark) {
            log::warn!(
                "peachy-mls: refused a Welcome at or below an epoch this device already held the \
                 group at"
            );
            return Err(Error::AlreadyAMember);
        }
        Ok(())
    }

    /// The roster a Welcome for `group_id` is held to: the people of the copy
    /// this device holds, when it still has a claim on it
    /// ([`Self::claim_of_held`]), and the roster it kept when it forgot the
    /// group ([`Self::forget_group`]). Empty only when it knows no such
    /// group: a held copy or a kept roster names at least this device's own
    /// person.
    fn known_roster(&self, group_id: &[u8]) -> Result<Vec<RosterClaim>> {
        let mut known = self.vouched_claim_of_held(group_id)?.unwrap_or_default();
        for remembered in self.provider.peachy_storage().remembered_roster(group_id)? {
            if !known.contains(&remembered) {
                known.push(remembered);
            }
        }
        Ok(known)
    }

    /// The people of a held copy, when this device still has a claim on it:
    /// it is active, or this device's own person still holds a leaf in it (a
    /// removal of this device alone, which it asks back in from). `None` for
    /// a copy this device was removed from together with its person: that
    /// removal was real, and a later Welcome is a new invitation.
    ///
    /// Every leaf counts, its person read from its credential without
    /// verifying it ([`PeachyIdentityProvider::claimed_person`]): each was
    /// verified when it arrived, and one that no longer verifies today (it
    /// lapsed, or the server stopped publishing its kid) is still somebody
    /// a replacing Welcome must draw as gone if it leaves them out.
    fn claim_of_held(&self, group: &MlsGroup) -> Option<Vec<RosterClaim>> {
        let mut claim: Vec<RosterClaim> = Vec::new();
        let mut own_person_seated = false;
        for member in group.members() {
            let Some((actor_id, device_id, account_key)) =
                PeachyIdentityProvider::claimed_person(&member.credential)
            else {
                continue;
            };
            if actor_id == self.identity.actor_id && device_id != self.identity.device_id {
                own_person_seated = true;
            }
            let entry = RosterClaim {
                actor_id,
                account_key,
            };
            if !claim.contains(&entry) {
                claim.push(entry);
            }
        }
        (group.is_active() || own_person_seated).then_some(claim)
    }

    /// Whether the signer of `seat`, a device of this device's own person,
    /// is one this device trusts to re-seat it in the group it knew: not
    /// this device's own id, not a device this account forgot (by its id or
    /// by any key it was seen holding), not one this device saw seated by a
    /// committer it did not trust, and on this device's approval chain
    /// ([`Self::own_device_anchors`]).
    ///
    /// The chain, whether this device is still active in the group or not.
    /// A sibling this device only saw in the group's tree vouches for
    /// nothing: group policy lets any device remove leaves of its own
    /// account, so such a sibling could first remove this device from the
    /// real group, making its copy inactive, and then re-seat it in a group
    /// of its own under the same id. Refused, that sibling's removal leaves
    /// this device's copy naming the real group's people, who re-seat it.
    fn own_signer_trusted(&self, seat: &StagedSeat) -> bool {
        let Some((device_id, device_key)) = seat.welcome_sender_device.as_ref() else {
            return false;
        };
        if *device_id == self.identity.device_id
            || self.is_forgotten_own_device(device_id, device_key)
        {
            return false;
        }
        let pair = (device_id.clone(), device_key.to_vec());
        let Ok(unvouched) = self.provider.peachy_storage().own_unvouched() else {
            return false;
        };
        if unvouched.contains(&pair) {
            return false;
        }
        self.own_device_anchors()
            .map(|anchors| anchors.contains(&pair))
            .unwrap_or(false)
    }

    /// Whether `seat` was signed by a device of this device's own person
    /// that the account forgot ([`Self::forget_own_device`]), by its id or by
    /// any key it was seen holding. A store that cannot answer is an error,
    /// not a verdict, so a read failure never spends a sibling's Welcome.
    fn signed_by_forgotten_own_device(&self, seat: &StagedSeat) -> Result<bool> {
        if seat.welcome_sender.as_deref() != Some(self.identity.actor_id.as_str()) {
            return Ok(false);
        }
        let Some((device_id, device_key)) = seat.welcome_sender_device.as_ref() else {
            return Ok(false);
        };
        Ok(self.own_device_id_forgotten(device_id)?
            || self
                .forgotten_own_keys()?
                .iter()
                .any(|key| key.as_slice() == device_key.as_slice()))
    }

    /// How `seat`, a Welcome into a group this device may know, is drawn.
    /// `Ok(None)` when this device knew no such group (a first join, drawn
    /// as one): it holds no copy under the id that it still has a claim on,
    /// and kept no roster for it (it never held the group, left it on
    /// purpose ([`Self::forget_remembered_roster`]), or was removed from it
    /// with its person). Any other Welcome under the id is drawn, a copy
    /// that names nobody but this device's own person included. Otherwise
    /// the lines its report carries ([`RejoinReport`]): who re-added this
    /// device, who the new tree brings and leaves out against the people
    /// this device last saw there (the copy held now and the roster kept
    /// when one was forgotten, matched by actor and account key, so the same
    /// actor under another key is one person gone and another added), and
    /// whether the admins changed against the group state it last saw from a
    /// copy a head matched.
    ///
    /// **Nobody is refused for who they are.** The device cannot tell a
    /// member's own copy under the id from the real group by what it held,
    /// so it takes the seat and says what changed, each Welcome as its own
    /// lines; the real group's Welcome at the head replaces such a copy
    /// ([`Self::join_from_welcome_at_head`]). The signer is drawn by name,
    /// except a device of this device's own person that is not on its
    /// approval chain ([`Self::own_signer_trusted`]), which is drawn as
    /// untrusted: the account key all of a person's devices share says
    /// nothing about which device signed.
    ///
    /// Refused, with [`Error::WelcomeFromOutsider`]: a Welcome signed by a
    /// device the account forgot, into any group, known or new (the server
    /// signs a removed device out with its removal, so no honest build ever
    /// sends from one); and a Welcome into a known group whose signer does
    /// not identify, so no line could say who it was.
    fn judge_replacing_welcome(&self, seat: &StagedSeat) -> Result<Option<Judged>> {
        if self.signed_by_forgotten_own_device(seat)? {
            log::warn!("peachy-mls: refused a Welcome signed by a device this account removed");
            return Err(Error::WelcomeFromOutsider);
        }
        let mut known = self.known_roster(&seat.group_id)?;
        let held = self.unvouched_held_roster(&seat.group_id)?;
        if known.is_empty() && held.is_empty() {
            return Ok(None);
        }
        let Some(sender) = seat.welcome_sender.as_deref() else {
            return Err(Error::WelcomeFromOutsider);
        };
        let untrusted = sender == self.identity.actor_id
            && !(seat.welcome_sender_key.is_some()
                && seat.welcome_sender_key == self.identity.account_key
                && self.own_signer_trusted(seat));
        for claim in held {
            if !known.contains(&claim) {
                known.push(claim);
            }
        }
        let (added, departed) =
            self.roster_change(&seat.group_id, &known, &self.people_of_staged(&seat.staged))?;
        let welcome_meta = group_meta_from_context(seat.staged.group_context().extensions());
        let admins_changed = self
            .known_policy(&seat.group_id)?
            .as_deref()
            .is_some_and(|before| admins_of(Some(before)) != admins_of(welcome_meta.as_deref()));
        if untrusted {
            log::warn!(
                "peachy-mls: took a Welcome into a group this device knew from a device of its \
                 own person it does not trust"
            );
        }
        let dropped_devices = self.dropped_devices(&seat.group_id, &seat.staged, &departed)?;
        if !dropped_devices.is_empty() {
            log::warn!(
                "peachy-mls: a Welcome into a group this device knew leaves out {} device(s) of \
                 people it keeps",
                dropped_devices.len()
            );
        }
        Ok(Some(Judged {
            untrusted,
            added: Self::actors_of(&added),
            departed: Self::actors_of(&departed),
            admins_changed,
            dropped_devices,
        }))
    }

    /// The devices, as (actor, device id), of the copy of `group_id` held now
    /// when this device still has a claim on it ([`Self::claim_of_held`]),
    /// each once, this device itself never among them.
    fn devices_of_held(&self, group_id: &[u8]) -> Vec<(String, String)> {
        let Some(group) = self.groups.get(group_id) else {
            return Vec::new();
        };
        if self.claim_of_held(group).is_none() {
            return Vec::new();
        }
        let mut devices: Vec<(String, String)> = Vec::new();
        for member in group.members() {
            let Some((actor_id, device_id, _)) =
                PeachyIdentityProvider::claimed_person(&member.credential)
            else {
                continue;
            };
            if device_id == self.identity.device_id {
                continue;
            }
            let entry = (actor_id, device_id);
            if !devices.contains(&entry) {
                devices.push(entry);
            }
        }
        devices
    }

    /// WHICH DEVICES A WELCOME LEAVES OUT of people it keeps
    /// ([`RejoinReport::dropped_devices`]): every device this device last saw
    /// in `group_id` (the copy held now, and the devices kept when a copy
    /// was forgotten or replaced) whose person the staged tree still holds
    /// and who is not among `departed`, while the tree holds no leaf of that
    /// device. Never this device, nor a device this account forgot. Sorted.
    fn dropped_devices(
        &self,
        group_id: &[u8],
        staged: &StagedWelcome,
        departed: &[RosterClaim],
    ) -> Result<Vec<(String, String)>> {
        let mut known = self.devices_of_held(group_id);
        for kept in self
            .provider
            .peachy_storage()
            .remembered_devices(group_id)?
        {
            if kept.1 != self.identity.device_id && !known.contains(&kept) {
                known.push(kept);
            }
        }
        if known.is_empty() {
            return Ok(Vec::new());
        }
        let mut seated_actors: Vec<String> = Vec::new();
        let mut seated_devices: Vec<(String, String)> = Vec::new();
        for member in staged.members() {
            let Some((actor_id, device_id, _)) =
                PeachyIdentityProvider::claimed_person(&member.credential)
            else {
                continue;
            };
            if !seated_actors.contains(&actor_id) {
                seated_actors.push(actor_id.clone());
            }
            seated_devices.push((actor_id, device_id));
        }
        let mut dropped: Vec<(String, String)> = known
            .into_iter()
            .filter(|(actor, _)| seated_actors.contains(actor))
            .filter(|(actor, _)| !departed.iter().any(|gone| &gone.actor_id == actor))
            .filter(|device| !seated_devices.contains(device))
            .filter(|(actor, device)| {
                actor != &self.identity.actor_id
                    || !self.own_device_id_forgotten(device).unwrap_or(true)
            })
            .collect();
        dropped.sort();
        dropped.dedup();
        Ok(dropped)
    }

    /// The people of a staged Welcome's tree, each leaf that identifies one
    /// read with every check but the clock, as (actor, account key), each
    /// once.
    fn people_of_staged(&self, staged: &StagedWelcome) -> Vec<RosterClaim> {
        let mut people: Vec<RosterClaim> = Vec::new();
        for member in staged.members() {
            if let Ok((identity, _)) = self.identity_provider.validate_seated_credential(
                &member.credential,
                &member.signature_key,
                i64::MAX,
            ) {
                let person = RosterClaim {
                    actor_id: identity.actor_id,
                    account_key: identity.account_key,
                };
                if !people.contains(&person) {
                    people.push(person);
                }
            }
        }
        people
    }

    /// What a Welcome whose tree holds `welcome` changes against `known`, as
    /// (added, departed), this device's own person never in either. A
    /// person is matched by actor and account key
    /// ([`RosterClaim::is_matched_by`]). Departed leaves out somebody this
    /// device already saw leave (`NS_DEPARTED`), but only when they hold no
    /// leaf in the copy held now: the exception is for a roster kept from a
    /// forgotten copy, never for somebody seated in the copy being replaced.
    fn roster_change(
        &self,
        group_id: &[u8],
        known: &[RosterClaim],
        welcome: &[RosterClaim],
    ) -> Result<(Vec<RosterClaim>, Vec<RosterClaim>)> {
        let me = self.identity.actor_id.as_str();
        let added: Vec<RosterClaim> = welcome
            .iter()
            .filter(|person| person.actor_id != me)
            .filter(|person| !known.iter().any(|claim| claim.is_matched_by(person)))
            .cloned()
            .collect();
        let mut departed: Vec<RosterClaim> = Vec::new();
        for claim in known {
            if claim.actor_id == me
                || welcome.iter().any(|person| claim.is_matched_by(person))
                || departed.contains(claim)
            {
                continue;
            }
            if !self.holds_leaf_of_actor(group_id, &claim.actor_id)
                && self
                    .provider
                    .peachy_storage()
                    .departed(group_id, &claim.actor_id)?
            {
                continue;
            }
            departed.push(claim.clone());
        }
        Ok((added, departed))
    }

    /// The actors of `people`, sorted, each once: what a report draws.
    fn actors_of(people: &[RosterClaim]) -> Vec<String> {
        let mut actors: Vec<String> = people.iter().map(|p| p.actor_id.clone()).collect();
        actors.sort();
        actors.dedup();
        actors
    }

    /// The group state (`peachy_group_meta`) a Welcome into `group_id` is
    /// drawn against for whether the admins changed
    /// ([`Self::judge_replacing_welcome`]): the
    /// state of the copy held now when a head vouched for it
    /// ([`Self::vouched_claim_of_held`]), else the state kept when a vouched
    /// copy was forgotten ([`Self::forget_group`]). `None` when this device
    /// knows no vouched state of the group, or the group carries none.
    fn known_policy(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.vouched_claim_of_held(group_id)?.is_some() {
            if let Some(group) = self.groups.get(group_id) {
                return Ok(group_meta_from_context(group.extensions()));
            }
        }
        Ok(self.provider.peachy_storage().remembered_policy(group_id)?)
    }

    /// The report a seat judged as `judged` leaves ([`RejoinReport`]).
    fn report_of(seat: &StagedSeat, judged: &Judged) -> Option<RejoinReport> {
        let readded_by = seat.welcome_sender.clone()?;
        Some(RejoinReport {
            readded_by,
            readded_by_device: seat
                .welcome_sender_device
                .as_ref()
                .map(|(device_id, _)| device_id.clone())
                .unwrap_or_default(),
            readded_by_untrusted: judged.untrusted,
            added_actors: judged.added.clone(),
            departed_actors: judged.departed.clone(),
            admins_changed: judged.admins_changed,
            contested: false,
            dropped_devices: judged.dropped_devices.clone(),
            id: 0,
            drawn_at_ms: 0,
        })
    }

    /// Keep `report` for the client after every report it has not taken yet
    /// ([`Self::take_rejoin_report`]). Past [`REJOIN_REPORTS_KEPT`], it is
    /// folded into the newest instead ([`RejoinReport::fold`]), so a stream
    /// of Welcomes cannot grow the store without bound; every flag and person
    /// is kept, and only the later re-adder is named.
    fn keep_rejoin_report(&self, group_id: &[u8], mut report: RejoinReport) -> Result<()> {
        if report.id == 0 {
            report.id = fresh_report_id()?;
        }
        let storage = self.provider.peachy_storage();
        let mut reports = storage.rejoin_reports(group_id)?;
        let full = reports.len() >= REJOIN_REPORTS_KEPT;
        match reports.last_mut() {
            Some(newest) if full => newest.fold(report),
            _ => reports.push(report),
        }
        storage.set_rejoin_reports(group_id, &reports)?;
        Ok(())
    }

    /// The oldest report a Welcome that restored or replaced `group_id`
    /// left, or a head left against the copy held ([`RejoinReport`]), left
    /// in place: the door the apps draw through. The caller draws it and
    /// then drops it by its id ([`Self::drop_rejoin_report`]), and peeks
    /// again until `None`, so each Welcome's report is drawn as its own
    /// lines, in order. A report stays kept until it is dropped, through a
    /// restart, a forget ([`Self::forget_group`]) and a process that died
    /// between drawing it and dropping it: the next peek answers it again.
    ///
    /// The first peek of a report records the time it is drawn at
    /// ([`RejoinReport::drawn_at_ms`]): `now_ms`, or, when an earlier report
    /// of the group was drawn later than that, the first millisecond after
    /// the ones that report owns. Each report owns
    /// [`RejoinReport::line_span`] milliseconds from its time, one for each
    /// line it can draw, so a caller that draws its line `i` at
    /// `drawn_at_ms + i` never lands two reports' lines on one time, however
    /// many passes meet the same `now_ms`. Every later peek answers that
    /// same time, so a caller that draws at it and keys each line by it
    /// rewrites the lines it already wrote rather than adding a second set.
    /// A stored report with no id is given its id here too.
    ///
    /// It writes (only the first time), under the store's write lock like
    /// every write door (§A store two processes share), so two processes
    /// peeking one report agree on its time.
    pub fn peek_rejoin_report(
        &mut self,
        group_id: &[u8],
        now_ms: u64,
    ) -> Result<Option<RejoinReport>> {
        self.synced(|client| {
            let storage = client.provider.peachy_storage();
            let mut reports = storage.rejoin_reports(group_id)?;
            let Some(oldest) = reports.first_mut() else {
                return Ok(None);
            };
            let mut changed = false;
            if oldest.id == 0 {
                oldest.id = fresh_report_id()?;
                changed = true;
            }
            if oldest.drawn_at_ms == 0 {
                // Never before the milliseconds the group's last report drawn
                // owns, and never 0, which reads as not fixed.
                let floor = storage.rejoin_draw_floor(group_id)?;
                let at = now_ms.max(floor).max(1);
                oldest.drawn_at_ms = at;
                storage.set_rejoin_draw_floor(group_id, at.saturating_add(oldest.line_span()))?;
                changed = true;
            }
            let answer = oldest.clone();
            if changed {
                storage.set_rejoin_reports(group_id, &reports)?;
            }
            Ok(Some(answer))
        })
    }

    /// Drop the report [`Self::peek_rejoin_report`] answered with `id`, once
    /// the caller drew it. Answers whether one was dropped: false when no
    /// report waiting has that id (another process drew and dropped it
    /// first), which is no error. Under the store's write lock.
    pub fn drop_rejoin_report(&mut self, group_id: &[u8], id: u64) -> Result<bool> {
        self.synced(|client| {
            let storage = client.provider.peachy_storage();
            let mut reports = storage.rejoin_reports(group_id)?;
            let Some(at) = reports.iter().position(|report| report.id == id) else {
                return Ok(false);
            };
            reports.remove(at);
            storage.set_rejoin_reports(group_id, &reports)?;
            Ok(true)
        })
    }

    /// The oldest report a Welcome that restored or replaced `group_id`
    /// left, or a head left against the copy held ([`RejoinReport`]), taken
    /// out at once: [`Self::peek_rejoin_report`] and
    /// [`Self::drop_rejoin_report`] in one step. A report taken is the
    /// caller's, and one taken but not yet drawn when the process dies is
    /// lost, so the apps draw through the peek; this is for a caller with
    /// nothing durable to draw. A report taken carries no id (there is
    /// nothing left to drop) and the time a peek fixed, if one did.
    ///
    /// It writes, under the store's write lock like every write door
    /// (§A store two processes share), so a Welcome another process joins
    /// meanwhile keeps its report after this take, never under it.
    pub fn take_rejoin_report(&mut self, group_id: &[u8]) -> Result<Option<RejoinReport>> {
        self.synced(|client| {
            let storage = client.provider.peachy_storage();
            let mut reports = storage.rejoin_reports(group_id)?;
            if reports.is_empty() {
                return Ok(None);
            }
            let mut oldest = reports.remove(0);
            storage.set_rejoin_reports(group_id, &reports)?;
            oldest.id = 0;
            Ok(Some(oldest))
        })
    }

    /// Drop the roster this device kept for `group_id` when it forgot it
    /// ([`Self::forget_group`]). For a person who LEFT on purpose: they have
    /// no claim on the group any more, and a later Welcome into it is a new
    /// invitation from whoever sends it, not a rejoin drawn against the old
    /// roster.
    /// A no-op when nothing is kept. The record of who left the group
    /// ([`Self::verify_join_request`]), any rejoin report not taken yet, the
    /// leaves the conversation settled for the security-code notice, and
    /// who each of its device keys belonged to (what names the sender of a
    /// sealed envelope, [`Self::next_reopenable`]) go with it: nothing of the
    /// group's people stays behind on this device, and no sealed envelope of
    /// it draws a conversation this person left back into sight.
    /// Under the store's write lock, as [`Self::take_rejoin_report`].
    pub fn forget_remembered_roster(&mut self, group_id: &[u8]) -> Result<()> {
        self.synced(|client| {
            let storage = client.provider.peachy_storage();
            storage.forget_remembered_roster(group_id)?;
            storage.forget_departed(group_id)?;
            storage.forget_rejoin_report(group_id)?;
            storage.forget_leaf_people(group_id)?;
            storage.forget_hold_history(group_id)?;
            storage.forget_account_leaf_records(group_id)?;
            Ok(())
        })
    }

    /// Keep a staged, verified Welcome: delete whatever this device held under
    /// its id, and seat it.
    ///
    /// `judged` is how the seat was judged, when it restored or replaced a
    /// group this device knew ([`Self::judge_replacing_welcome`]): a
    /// [`RejoinReport`] is kept for the client, and the people of the known
    /// roster it leaves out are recorded as departed.
    ///
    /// `head_checked`: the seat was taken against the group's head, so its
    /// epoch is one the head bounds and raises the epoch mark. `confirmed`:
    /// it was taken AT the head, so the copy is confirmed
    /// ([`Self::confirm_head`]), and only then is the roster kept from an
    /// earlier forget spent. `join_head`: the head a seat taken BELOW it was
    /// taken against, kept to hold the copy to once it gets there.
    ///
    /// A replaced copy a head vouched for leaves its people behind as a
    /// forget does ([`Self::remember_held_copy`]) when the new seat is not
    /// confirmed, so the next Welcome is drawn against who the group's
    /// people were, less whoever this seat leaves out.
    fn take_seat(
        &mut self,
        seat: StagedSeat,
        judged: Option<Judged>,
        head_checked: bool,
        confirmed: bool,
        join_head: Option<(u64, [u8; 32])>,
    ) -> Result<Vec<u8>> {
        let report = judged
            .as_ref()
            .and_then(|judged| Self::report_of(&seat, judged));
        // WHO LEFT WHILE THIS DEVICE WAS AWAY: the people of the roster it
        // knew whom the new tree leaves out. Judged like a removal it saw
        // (`verify_join_request`).
        let departed = judged
            .as_ref()
            .map(|judged| judged.departed.clone())
            .unwrap_or_default();
        let StagedSeat {
            group_id,
            staged,
            sealed_to,
            welcome_sender,
            welcome_sender_key: _,
            welcome_sender_device: _,
            taken_key,
            gap_block,
        } = seat;
        // Only now, with the new group verified, does the old one go — all of
        // it, so no epoch secret of the branch this device fell off survives
        // under the id the new group is about to be stored at. Never one that
        // holds a saved commit: the head settles that first. Its epoch stays
        // behind as the group's mark ([`Self::epoch_mark`]).
        self.refuse_unsettled(&group_id)?;
        if !confirmed {
            self.remember_held_copy(&group_id)?;
        }
        self.raise_epoch_mark_to_held(&group_id)?;
        if let Some(mut old) = self.groups.remove(&group_id) {
            old.delete(self.provider.storage()).map_err(|err| {
                Error::Mls(format!("could not delete the replaced group state: {err}"))
            })?;
            self.refused_commits.remove(&group_id);
        }
        let storage = self.provider.peachy_storage();
        storage.forget_copy_records(&group_id)?;
        storage.set_head_state(&group_id, HeadState::Unconfirmed)?;
        if let Some((epoch, verifier)) = join_head {
            storage.set_join_head(&group_id, epoch, &verifier)?;
        }

        let group = staged.into_group(&self.provider).map_err(mls_err)?;
        let group_id = group.group_id().as_slice().to_vec();
        let seated_epoch = group.epoch().as_u64();
        self.groups.insert(group_id.clone(), group);
        self.provider.peachy_storage().remember_group(&group_id)?;
        if let Some(block) = gap_block {
            self.keep_welcome_gap(&group_id, seated_epoch, &block)?;
        }
        // A seat the head bounds raises the mark; one taken with no head
        // (`join_from_welcome`) raises nothing until a head confirms it.
        if head_checked {
            self.provider
                .peachy_storage()
                .raise_epoch_mark(&group_id, seated_epoch)?;
        }
        // The rejoin landed AT THE HEAD: the roster kept for it is spent.
        // A seat below the head, or with none, keeps it until the copy is
        // confirmed (`note_head_confirmed`): a seat in somebody's own group
        // under the id must not throw away who the real group's people are.
        // What the new tree brought is kept for the client to draw.
        if confirmed {
            self.note_head_confirmed(&group_id)?;
            self.provider
                .peachy_storage()
                .vouch_head_epoch(&group_id, seated_epoch)?;
        }
        // A seat is no merge: the meta it brings counts as it stands.
        self.steward_merges.remove(&group_id);
        self.note_copy_epoch(&group_id)?;
        self.note_departed(&group_id, &departed)?;
        // Then whoever the new tree seats has not left, an actor the report
        // names as gone under one account key and back under another
        // included.
        self.clear_departed_of_seated(&group_id)?;
        if let Some(report) = report {
            self.keep_rejoin_report(&group_id, report)?;
        }
        match &welcome_sender {
            Some(actor) => self
                .provider
                .peachy_storage()
                .set_welcome_sender(&group_id, actor)?,
            None => self
                .provider
                .peachy_storage()
                .forget_welcome_sender(&group_id)?,
        }
        // The leaf a Welcome seats is the key package's. A ONE-TIME package was
        // minted for this join, so its leaf is as fresh as a rotation. A
        // LAST-RESORT package's is not: its leaf HPKE key is the same in every
        // group that package has seated, so the leaf is marked due at once and
        // the device's next send replaces it (RFC 9420 §16.8 on reuse; the
        // replacement is §Periodic leaf rotation's own path).
        let via_last_resort = self
            .provider
            .peachy_storage()
            .last_resorts()?
            .into_iter()
            .find(|(reference, _)| sealed_to.contains(reference))
            .map(|(reference, _)| reference);
        if let Some(reference) = via_last_resort {
            // The package opens this Welcome for as long as its private half
            // is kept, so the taking is remembered for as long
            // ([`Self::prune_last_resorts`] drops both together).
            self.provider
                .peachy_storage()
                .note_welcome_taken(&taken_key, &reference)?;
            let now = self.identity_provider.now_unix();
            self.provider.peachy_storage().set_leaf_rotation(
                &group_id,
                now,
                LEAF_ROTATION_FRAME_BUDGET,
            )?;
            self.provider.peachy_storage().clear_peer_heard(&group_id)?;
        } else {
            self.note_fresh_leaf(&group_id)?;
        }
        // Not flushed here: both doors that seat flush on every outcome, and
        // erase what the Welcome's key package and a replaced group's state
        // left behind, not just unlink it.
        Ok(group_id)
    }

    /// The roster, each entry carrying its verification result.
    ///
    /// **A person's leaf whose credential expired less than
    /// [`EXPIRED_LEAF_GRACE_SECONDS`](crate::identity::EXPIRED_LEAF_GRACE_SECONDS)
    /// ago reads `Ok`**, with its past `expires_at` showing, and only past the
    /// grace as `Err(Expired)`. The same grace [`Self::process`] extends to
    /// that leaf's messages, and it has to reach the roster too, because every
    /// client removes a leaf it cannot identify, before its next send into the
    /// group and in its foreground pass (never on opening a conversation,
    /// docs/identity.md §Refreshing a seated leaf). A lapsed leaf read
    /// as unidentifiable was evicted by whichever member reached it first, on
    /// the day it lapsed — and that eviction was the conversation breaking,
    /// not a repair of it.
    pub fn roster(&self, group_id: &[u8]) -> Result<Vec<RosterEntry>> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        Ok(group
            .members()
            .map(|member| self.roster_entry(member))
            .collect())
    }

    /// The one roster entry at `leaf_index`, `None` when the tree holds no
    /// member there: [`Self::roster`] for a single leaf, validating only that
    /// leaf's credential. What a door that judges one claimed leaf reads (a
    /// live call frame, opened before its replay check), so a frame the
    /// server repeats costs one credential check, not one per member.
    pub(crate) fn roster_entry_at(
        &self,
        group_id: &[u8],
        leaf_index: u32,
    ) -> Result<Option<RosterEntry>> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        Ok(group
            .member_at(LeafNodeIndex::new(leaf_index))
            .map(|member| self.roster_entry(member)))
    }

    fn roster_entry(&self, member: openmls::prelude::Member) -> RosterEntry {
        RosterEntry {
            leaf_index: member.index.u32(),
            identity: self
                .identity_provider
                .validate_seated_credential(
                    &member.credential,
                    &member.signature_key,
                    crate::identity::EXPIRED_LEAF_GRACE_SECONDS,
                )
                .map(|(identity, _lapsed)| identity)
                .map_err(|err| match err {
                    Error::CredentialRejected(reason) => reason,
                    // Validation only ever returns CredentialRejected;
                    // anything else is a bug, reported as a malformed
                    // credential rather than swallowed or panicked on.
                    _ => CredentialRejection::Malformed,
                }),
            leaf_key: member.signature_key,
        }
    }

    /// Compare every other actor's CURRENT account identity key in `group_id`
    /// with the key this device last accepted for them, and return the actors
    /// whose key CHANGED — the "security code changed" notice
    /// (docs/identity.md §Security code changed).
    ///
    /// Trust on first use: the first sight of an actor accepts, in silence,
    /// every key that tree shows for them, and pins as current the key of
    /// their newest leaf (the highest signed `iat`); the others are recorded
    /// as keys they moved away from. After that a change is reported — once
    /// per conversation it is seen in, so each conversation with that person
    /// says so — and never refused: a new key is what losing every device
    /// looks like, and the notice is the person's cue to check. What a server
    /// CANNOT do is add a device under the key already pinned, since only the
    /// account's own devices can sign for it ([`crate::account_identity`]).
    ///
    /// Every leaf of theirs not under the current key is a change, said once
    /// in each conversation that shows it, unless that conversation already
    /// settled it (it showed it under the key then current, or reported it).
    /// A leaf under a key they moved away from has no exemption, whoever put
    /// it in the tree and however old its credential: a Welcome's tree is
    /// its committer's choice, and the conversation encrypts to that leaf. A
    /// key never accepted is always a change. A report settles a leaf only
    /// while its key is not the person's current one: whenever the pin
    /// moves, every conversation drops its reports of their leaves under the
    /// key it moved to or off (a copy forgotten for a rejoin, at its next
    /// read), so a leaf under that key is named once in each conversation
    /// still showing it after the person moves off the key, whichever
    /// conversations were read in between. A conversation keeps no leaf as
    /// both settled and reported: a report of a leaf it settled while that
    /// leaf's key was current is dropped at the read.
    ///
    /// The pin moves to a reported leaf only when it was issued after the
    /// leaf that made the current key current (a key never accepted: not
    /// before, since the issuer floors `iat` to the day), and never when its
    /// `iat` is more than [`ACCOUNT_KEY_FUTURE_SKEW_SECONDS`] past this
    /// device's clock; the pin is dated no later than that clock. An older or
    /// future-dated one is reported, accepted as a key they moved away from,
    /// and the live key stays, so their next device under it says nothing and
    /// a reseat under it still goes through ([`Self::reseat_person`]).
    ///
    /// Each conversation keeps the key it last showed as the person's current
    /// one, and reports the first current key it shows after showing them
    /// only under another, so a change made elsewhere is said there once,
    /// when its tree carries it. A forgotten copy starts over. A pin with no
    /// time recorded learns when it became current only from leaves under it,
    /// and the keys a conversation with no `known` record showed there count
    /// as accepted, never as current. This device's own actor is skipped: its
    /// own account's key is not a stranger's claim.
    ///
    /// Call it after anything that can change a tree: a merged own commit, a
    /// processed commit, a joined Welcome. It writes, under the store's
    /// write lock like every write door (§A store two processes share), so
    /// it pins from the tree as the store holds it now, and is idempotent.
    pub fn observe_account_keys(&mut self, group_id: &[u8]) -> Result<Vec<String>> {
        self.synced(|client| client.observe_account_keys_now(group_id))
    }

    /// [`Self::observe_account_keys`], inside its door.
    fn observe_account_keys_now(&self, group_id: &[u8]) -> Result<Vec<String>> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        let storage = self.provider.peachy_storage();
        self.redate_undated_pins()?;
        let (people, in_tree) = self.shown_people(group);
        // Records of leaves no longer in the tree go: a leaf that leaves and
        // is added back is judged again.
        let now = self.device_now_unix();
        let stored_known = storage.account_known_leaves(group_id)?;
        let stored_reported = storage.account_reported_leaves(group_id)?;
        let legacy = stored_known.is_none();
        let mut known = stored_known.clone().unwrap_or_default();
        known.retain(|leaf| in_tree.contains(leaf));
        let mut reported = stored_reported.clone().unwrap_or_default();
        reported.retain(|leaf| in_tree.contains(leaf));
        // A leaf is never in both records after a read (the end of this one
        // drops each it reported from `known`). One a store holds in both
        // was settled while its key was current, and that report settles
        // nothing: kept as settled only, the leaf is named once the person
        // is, or later is, off its key, as any leaf left behind under a key
        // the person moved off is. A conversation that already named it then
        // names it once more.
        reported.retain(|leaf| !known.contains(leaf));
        // A copy forgotten for a rejoin missed the pin moves made while it
        // was not held: its reports of a leaf under a key a pin moved to or
        // off meanwhile go now, as the prune would have dropped them
        // (`Self::settle_reports_on_pin_move`).
        let moved_while_forgotten = storage.account_moved_while_forgotten(group_id)?;
        for (actor_id, keys) in &moved_while_forgotten {
            if let Some(leaves) = people.get(actor_id) {
                reported.retain(|digest| {
                    !leaves
                        .iter()
                        .any(|l| l.leaf == *digest && keys.contains(&l.account_key))
                });
            }
        }
        if !moved_while_forgotten.is_empty() {
            storage.forget_account_moved_while_forgotten(group_id)?;
        }
        let mut changed = Vec::new();
        for (actor_id, leaves) in people {
            // A stored record with no reported list holds reported leaves
            // beside settled ones: a leaf it holds under a key that is not current
            // now was reported (or accepted) there, and stays settled.
            if stored_known.is_some() && stored_reported.is_none() {
                let pins = storage.account_pins(&actor_id)?;
                let before = reported.len();
                reported.extend(
                    leaves
                        .iter()
                        .filter(|l| known.contains(&l.leaf) && !pins.contains(&l.account_key))
                        .map(|l| l.leaf),
                );
                // So the conversation counts as having said the move: a leaf
                // the person adds later under the live key is no second
                // notice there.
                if reported.len() > before && !pins.is_empty() {
                    storage.set_account_seen(group_id, &actor_id, &pins)?;
                }
            }
            let conversation = ConversationLeaves {
                known: &mut known,
                reported: &mut reported,
                legacy,
            };
            let pins_before = storage.account_pins(&actor_id)?;
            let report = observe_person(storage, group_id, &actor_id, &leaves, conversation, now)?;
            // This conversation's own records drop its reports under the new
            // key in `observe_person`; every other one, here.
            self.settle_reports_on_pin_move(&actor_id, &pins_before, Some(group_id))?;
            if report {
                changed.push(actor_id);
            }
        }
        // A reported leaf is settled by its report alone, while its key is
        // not current; were it in `known` too, the next read could not tell
        // it from a leaf both records hold for no reason.
        known.retain(|leaf| !reported.contains(leaf));
        known.sort_unstable();
        known.dedup();
        if stored_known.as_ref() != Some(&known) {
            storage.set_account_known_leaves(group_id, &known)?;
        }
        reported.sort_unstable();
        reported.dedup();
        if stored_reported.as_ref() != Some(&reported) {
            storage.set_account_reported_leaves(group_id, &reported)?;
        }
        Ok(changed)
    }

    /// CARRY THE VERSION-1 LEAF RECORDS, once: they were kept by the
    /// leaf's keys alone ([`account_leaf_digest_v1`]). For each held or
    /// leaving group with no record by [`account_leaf_digest`], each leaf
    /// its stored tree holds whose old digest a `known` record names, and
    /// whose credential validates under an account key this device had
    /// accepted for its actor (`account_pins` or `account_retired`), is
    /// carried to its digest now. No `reported` record is carried: a
    /// version-1 record cannot tell the leaf it reported from another seated
    /// on its keys, and a report under the key current now settles nothing
    /// (each read drops it). So a carried leaf under a key the person moved
    /// away from is named once more at the first read, and one under the
    /// current key once the person moves off it, as any settled leaf left
    /// behind under such a key is. A leaf no version-1 record judged, under
    /// a key never accepted for its actor, is not carried: the first read
    /// judges it.
    ///
    /// It runs under the write lock, at the first open that takes it
    /// without waiting; an open that finds it held leaves it to the next,
    /// and this device may process commits before then, or forget a copy
    /// and join it again. So these key rules, not the timing, are what keep
    /// a leaf a later commit seats on a recorded leaf's keys from being
    /// settled in silence. A group a read judged meanwhile has its own
    /// records and is passed over. The old records are then dropped, those
    /// of a copy forgotten and not joined again with them.
    fn carry_leaf_records_v1(&self) -> Result<()> {
        let storage = self.provider.peachy_storage();
        for (group_id, group) in self.groups.iter().chain(self.leaving.iter()) {
            if storage.account_known_leaves(group_id)?.is_some() {
                continue;
            }
            let (Some(old_known), _) = storage.account_leaf_records_v1(group_id)? else {
                continue;
            };
            let mut carried: Vec<[u8; 32]> = Vec::new();
            for member in group.members() {
                let Some(v2) = account_leaf_digest(&member) else {
                    continue;
                };
                let Ok((identity, _)) = self.identity_provider.validate_seated_credential(
                    &member.credential,
                    &member.signature_key,
                    i64::MAX,
                ) else {
                    continue;
                };
                let Some(key) = identity.account_key else {
                    continue;
                };
                // A record settles a leaf only under a key this device
                // accepted for its actor; a leaf no version-1 record judged
                // is judged at the first read.
                if !storage.account_pins(&identity.actor_id)?.contains(&key)
                    && !storage.account_retired(&identity.actor_id)?.contains(&key)
                {
                    continue;
                }
                if old_known.contains(&account_leaf_digest_v1(&member)) {
                    carried.push(v2);
                }
            }
            storage.set_account_known_leaves(group_id, &carried)?;
            // Written, and empty: a conversation with `known` and no
            // `reported` has its report seeded from `known` at the first
            // read, which would settle a carried leaf under a retired key in
            // silence.
            storage.set_account_reported_leaves(group_id, &[])?;
        }
        storage.forget_every_account_leaf_record_v1()?;
        Ok(())
    }

    /// WHEN A PERSON'S PIN MOVES, every conversation but `except` drops its
    /// reports of their leaves under a key the pin moved to or off (one in
    /// the pins now or in `before`, not both). A report settles a leaf only
    /// while its key is not current, and a read drops one under the key
    /// current then; a conversation not read while the key is current would
    /// otherwise keep the report after the person moves off that key again,
    /// and never name a leaf it still encrypts to. This core leaves no
    /// report under the current key, but a store it did not write can hold
    /// one, made while the key was not current and never dropped when it
    /// became current, or carried from the version-1 records; dropping the
    /// reports under the key moved off repairs it for a key move this core
    /// makes, whenever that store was written. A leaf dropped here is in
    /// neither record: read while its key is current, it is settled in
    /// silence; read after the person moved off the key, it is named there
    /// once.
    ///
    /// A held or leaving copy is pruned from its tree, and loses too every
    /// report of a leaf its tree no longer holds, as its next read would:
    /// a leaf removed and then added back on the same keys and credential
    /// is judged afresh, whatever pins moved meanwhile. A copy forgotten for
    /// a rejoin keeps its records but has no tree, so the keys are recorded
    /// for it (`account_moved_while_forgotten`), and its next read, the one
    /// after the rejoin, drops its reports under them.
    fn settle_reports_on_pin_move(
        &self,
        actor_id: &str,
        before: &[[u8; 32]],
        except: Option<&[u8]>,
    ) -> Result<()> {
        let storage = self.provider.peachy_storage();
        let pins = storage.account_pins(actor_id)?;
        let moved: Vec<[u8; 32]> = pins
            .iter()
            .filter(|key| !before.contains(key))
            .chain(before.iter().filter(|key| !pins.contains(key)))
            .copied()
            .collect();
        if moved.is_empty() {
            return Ok(());
        }
        for (group_id, reported) in storage.account_reported_leaf_records()? {
            if except == Some(group_id.as_slice()) || reported.is_empty() {
                continue;
            }
            let Some(group) = self
                .groups
                .get(&group_id)
                .or_else(|| self.leaving.get(&group_id))
            else {
                storage.add_account_moved_while_forgotten(&group_id, actor_id, &moved)?;
                continue;
            };
            let (mut people, in_tree) = self.shown_people(group);
            let leaves = people.remove(actor_id).unwrap_or_default();
            let kept: Vec<[u8; 32]> = reported
                .iter()
                .filter(|digest| {
                    in_tree.contains(digest)
                        && !leaves
                            .iter()
                            .any(|l| l.leaf == **digest && moved.contains(&l.account_key))
                })
                .copied()
                .collect();
            if kept.len() != reported.len() {
                storage.set_account_reported_leaves(&group_id, &kept)?;
            }
        }
        Ok(())
    }

    /// Every other person's identified leaves in `group`'s tree, by actor,
    /// and the digest of every leaf in it.
    fn shown_people(&self, group: &MlsGroup) -> (BTreeMap<String, Vec<ShownLeaf>>, Vec<[u8; 32]>) {
        let mut people: BTreeMap<String, Vec<ShownLeaf>> = BTreeMap::new();
        let mut in_tree: Vec<[u8; 32]> = Vec::new();
        for member in group.members() {
            let Some(leaf) = account_leaf_digest(&member) else {
                continue;
            };
            in_tree.push(leaf);
            let Ok((identity, _)) = self.identity_provider.validate_seated_credential(
                &member.credential,
                &member.signature_key,
                i64::MAX,
            ) else {
                continue;
            };
            if identity.actor_id == self.identity.actor_id {
                continue;
            }
            if let Some(account_key) = identity.account_key {
                people
                    .entry(identity.actor_id)
                    .or_default()
                    .push(ShownLeaf {
                        account_key,
                        issued_at: identity.issued_at,
                        leaf,
                    });
            }
        }
        (people, in_tree)
    }

    /// DATE EVERY PIN WITH NO TIME RECORDED FROM EVERY CONVERSATION AT ONCE,
    /// before the first notice this build judges. Such a pin has no record of when it
    /// became current, and dating it from whichever tree is read first made
    /// the answer depend on the read order: a conversation still showing an
    /// old phone, read first, dated the old key as current, and the person's
    /// next device under their live key then read as a change in every
    /// conversation with them.
    ///
    /// Once per store: for each such person, the newest leaf (by
    /// [`newest_believable`]) any held tree shows under the pinned key, or
    /// under a key a conversation with no `known` record accepted for them
    /// (its `account_seen`) and this device never retired, becomes the pin, dated
    /// by it, in silence; the other keys among those are retired. A person no
    /// tree shows under such a key keeps the undated pin, which a later tree
    /// dates ([`observe_person`]).
    fn redate_undated_pins(&self) -> Result<()> {
        let storage = self.provider.peachy_storage();
        if storage.account_pins_dated()? {
            return Ok(());
        }
        let undated = storage.actors_with_undated_pins()?;
        if !undated.is_empty() {
            let now = self.device_now_unix();
            let mut shown: BTreeMap<String, Vec<ShownLeaf>> = BTreeMap::new();
            for (group_id, group) in &self.groups {
                let legacy = storage.account_known_leaves(group_id)?.is_none();
                for (actor_id, leaves) in self.shown_people(group).0 {
                    if !undated.contains(&actor_id) {
                        continue;
                    }
                    let pins = storage.account_pins(&actor_id)?;
                    let retired = storage.account_retired(&actor_id)?;
                    let accepted: Vec<[u8; 32]> = if legacy {
                        storage
                            .account_seen(group_id, &actor_id)?
                            .into_iter()
                            .filter(|k| !retired.contains(k))
                            .collect()
                    } else {
                        Vec::new()
                    };
                    shown
                        .entry(actor_id)
                        .or_default()
                        .extend(leaves.into_iter().filter(|l| {
                            pins.contains(&l.account_key) || accepted.contains(&l.account_key)
                        }));
                }
            }
            for (actor_id, leaves) in shown {
                let Some(leaf) = newest_believable(leaves.iter(), now) else {
                    continue;
                };
                let key = leaf.account_key;
                let pins = storage.account_pins(&actor_id)?;
                let mut retired = storage.account_retired(&actor_id)?;
                retired.extend(
                    pins.iter()
                        .chain(leaves.iter().map(|l| &l.account_key))
                        .copied()
                        .filter(|k| *k != key),
                );
                retired.sort_unstable();
                retired.dedup();
                storage.set_account_pins(&actor_id, &[key])?;
                storage.set_account_retired(&actor_id, &retired)?;
                if let Some(since) = latest_under(&leaves, &key, now) {
                    storage.set_account_pin_since(&actor_id, since)?;
                }
                self.settle_reports_on_pin_move(&actor_id, &pins, None)?;
            }
        }
        self.repair_order_dated_pins(&undated)?;
        storage.set_account_pins_dated()?;
        Ok(())
    }

    /// UNDO A RE-DATE THAT READ THE TREES IN THE WRONG ORDER, in the same
    /// once-per-store pass ([`Self::redate_undated_pins`]). A store can hold
    /// a pin with no time recorded that was dated from whichever tree was
    /// read first: a conversation showing only an old phone, read first,
    /// dated the old key, and a conversation that had accepted both keys
    /// then retired the live key as merely accepted, settling its leaf.
    ///
    /// The shape that leaves is narrow: a conversation whose `account_seen`
    /// still holds several keys (any report rewrites it to the pin alone),
    /// the pinned key among them, a leaf record not read since it was
    /// written (`account_known_leaves` without
    /// `account_reported_leaves`), and in its tree, settled in that record,
    /// a leaf under a RETIRED key of that same `account_seen`, believable and
    /// issued after the pin's `since`. Such a leaf's key takes the pin, in
    /// silence, dated by the latest leaf under that key, only when the leaf
    /// is the pick [`newest_believable`] makes among these candidates and
    /// every leaf any held tree shows under the pinned key. Both keys were
    /// accepted together in that
    /// conversation. Nothing else moves: a leaf under a retired key that was
    /// not settled beside the pin (a real change back, or a key a
    /// conversation reported) stays a change, and a key never accepted is
    /// never a candidate.
    fn repair_order_dated_pins(&self, undated: &[String]) -> Result<()> {
        let storage = self.provider.peachy_storage();
        let now = self.device_now_unix();
        let bound = now.saturating_add(ACCOUNT_KEY_FUTURE_SKEW_SECONDS);
        let mut shown: BTreeMap<String, Vec<ShownLeaf>> = BTreeMap::new();
        let mut under_pin: BTreeMap<String, Vec<ShownLeaf>> = BTreeMap::new();
        for (group_id, group) in &self.groups {
            let known = storage.account_known_leaves(group_id)?;
            let unread = storage.account_reported_leaves(group_id)?.is_none();
            for (actor_id, leaves) in self.shown_people(group).0 {
                if undated.contains(&actor_id) {
                    continue;
                }
                let pins = storage.account_pins(&actor_id)?;
                under_pin.entry(actor_id.clone()).or_default().extend(
                    leaves
                        .iter()
                        .filter(|l| pins.contains(&l.account_key))
                        .copied(),
                );
                let Some(known) = known.as_ref().filter(|_| unread) else {
                    continue;
                };
                let seen = storage.account_seen(group_id, &actor_id)?;
                if seen.len() < 2 {
                    continue;
                }
                if pins.len() != 1 || !seen.contains(&pins[0]) {
                    continue;
                }
                let retired = storage.account_retired(&actor_id)?;
                shown
                    .entry(actor_id)
                    .or_default()
                    .extend(leaves.into_iter().filter(|l| {
                        retired.contains(&l.account_key)
                            && seen.contains(&l.account_key)
                            && known.contains(&l.leaf)
                    }));
            }
        }
        for (actor_id, leaves) in shown {
            let Some(since) = storage.account_pin_since(&actor_id)? else {
                continue;
            };
            let candidates = leaves
                .iter()
                .filter(|l| l.issued_at <= bound && l.issued_at > since);
            if candidates.clone().next().is_none() {
                continue;
            }
            let pinned = under_pin.get(&actor_id).map(Vec::as_slice).unwrap_or(&[]);
            let Some(leaf) = newest_believable(candidates.chain(pinned.iter()), now) else {
                continue;
            };
            let key = leaf.account_key;
            let pins = storage.account_pins(&actor_id)?;
            if pins.contains(&key) {
                continue;
            }
            let mut retired = storage.account_retired(&actor_id)?;
            retired.extend(pins.iter().copied());
            retired.retain(|k| *k != key);
            retired.sort_unstable();
            retired.dedup();
            storage.set_account_pins(&actor_id, &[key])?;
            storage.set_account_retired(&actor_id, &retired)?;
            if let Some(dated) = latest_under(&leaves, &key, now) {
                storage.set_account_pin_since(&actor_id, dated)?;
            }
            self.settle_reports_on_pin_move(&actor_id, &pins, None)?;
            log::info!(
                "peachy-mls: a pin dated from one conversation moved to the newer key \
                 accepted beside it"
            );
        }
        Ok(())
    }

    /// The identity inside a raw key package, read out of the BYTES rather
    /// than taken from whoever handed them over.
    ///
    /// ## Why a client needs this at all
    ///
    /// Before a device seats another device of its OWN account, it checks
    /// that device's stored approval against a key it already trusts: its
    /// own, the device that let it in, or a leaf of its account in a group it
    /// holds ([`Client::check_own_device_approval`], docs/identity.md
    /// §What the adder checks). That check needs the NEW device's `device_id` and
    /// its signing key — and both have to come from the key package the
    /// adder is about to commit, never from the directory response that
    /// carried it. This is where they come from.
    ///
    /// The attack that rules out is small and complete. A server that wanted
    /// an unapproved leaf in a group would answer the key-package fetch with a
    /// truthful `(device_id, signing_key)` pair for the approval check and a
    /// key package carrying a DIFFERENT key. Every signature verifies, the
    /// approval holds, and the leaf that lands is one nobody ever approved.
    /// Reading the pair out of the package itself closes it: there is then one
    /// value, and the thing that was approved is the thing that is added.
    ///
    /// ## What it returns
    ///
    /// The same nested shape [`RosterEntry::identity`] carries, for the same
    /// reason:
    ///
    /// - `Err(_)` — the bytes are not a key package this build will accept at
    ///   all: not an `MlsMessage`, not a KeyPackage inside one, one whose
    ///   own signature does not check out, or one whose lifetime an add
    ///   refuses (`crate::key_package_lifetime`). The parse is deliberately the same
    ///   one [`Client::add_member`] does, so an input this accepts is an input
    ///   that can actually be added and no client has to learn two encodings.
    /// - `Ok(Err(rejection))` — a well-formed key package whose Peachy
    ///   credential does not verify: expired, an unknown issuer, a leaf key
    ///   the credential does not bind. A VERDICT, not a failure, exactly as on
    ///   the roster — the caller's move is to refuse the add and say why.
    /// - `Ok(Ok(identity))` — the actor, the device and the device key the
    ///   credential binds, which is also the leaf's signature key.
    ///
    /// It asks nothing of any group: a key package is a stranger's offer to
    /// join one, and the verdict on it is the same whether the reader is in
    /// one group or none.
    pub fn key_package_identity(
        &self,
        key_package: &[u8],
    ) -> Result<std::result::Result<PeachyIdentity, CredentialRejection>> {
        let message = MlsMessageIn::tls_deserialize_exact(key_package)?;
        let MlsMessageBodyIn::KeyPackage(incoming) = message.extract() else {
            return Err(Error::invalid("that message is not a KeyPackage"));
        };
        // The lifetime too, as an add judges it (`validated_key_package`), so
        // the two read a package alike.
        let key_package = Self::adder_checked(&self.provider, &self.identity_provider, incoming)?;
        Ok(self
            .identity_provider
            .validate_key_package(&key_package)
            .map_err(|err| match err {
                Error::CredentialRejected(reason) => reason,
                // validate_key_package only ever returns CredentialRejected;
                // anything else is a bug, reported as a malformed credential
                // rather than swallowed or panicked on.
                _ => CredentialRejection::Malformed,
            }))
    }

    /// Sign a request to be seated in `group_id`, as this device, now.
    ///
    /// Returns the 89-byte proof (`crate::join_request`): the time off this
    /// client's clock, a fresh random nonce, and this device's signature over
    /// both, the group, and its own actor and device ids. The ask it rides in
    /// still names the actor and device in the clear. The proof is what makes
    /// that claim checkable.
    pub fn sign_join_request(&self, group_id: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; crate::join_request::JOIN_REQUEST_NONCE_BYTES];
        getrandom::fill(&mut nonce)
            .map_err(|err| Error::invalid(format!("no randomness for a join request: {err}")))?;
        let issued_at = self.identity_provider.now_unix();
        let statement = crate::join_request::join_request_statement(
            group_id,
            &self.identity.actor_id,
            &self.identity.device_id,
            issued_at,
            &nonce,
        )?;
        // The leaf's own signer: the same Ed25519 key the credential binds.
        let signature = openmls_traits::signatures::Signer::sign(&self.signer, &statement)
            .map_err(|err| Error::Mls(format!("could not sign a join request: {err:?}")))?;
        if signature.len() != crate::join_request::JOIN_REQUEST_SIGNATURE_BYTES {
            return Err(Error::Mls(format!(
                "a join request signature came back {} bytes long",
                signature.len()
            )));
        }
        Ok(crate::join_request::assemble_proof(
            issued_at, &nonce, &signature,
        ))
    }

    /// Whether `(actor_id, device_id)`'s signed request to be seated in
    /// `group_id` holds, checked against `key_package`: the package fetched to
    /// seat that device.
    ///
    /// The asker's identity and signature key are read out of the key package
    /// through [`Client::key_package_identity`], so the credential is checked
    /// against the issuer keys this client trusts and at its clock. A package
    /// that does not parse or whose credential does not verify is
    /// [`JoinRequestVerdict::CredentialRejected`]. Everything else is
    /// [`crate::join_request::check_join_request`], and then membership.
    /// Never fails.
    ///
    /// **A signed ask proves who is asking, never that they belong.** A
    /// removed member keeps the group id and its own signing key, so it can
    /// sign an ask as well as anybody. A request that holds in every other way
    /// is still [`JoinRequestVerdict::NotAMember`] unless `actor_id`:
    ///
    /// - holds a leaf in this device's own copy of `group_id` (a lapsed leaf
    ///   counts: its person is still a member, and re-seating them is what a
    ///   rejoin is for);
    /// - is this device's own person; or
    /// - is in `pending_actors`: the people this device is itself trying to
    ///   seat and has not yet, such as a person picked when the group was made
    ///   who had no device then. The caller names them from its own list of
    ///   invitations, never from the ask; the core never infers them.
    ///
    /// **`pending_actors` never re-seats somebody who left.** A person whose
    /// last leaf this device saw leave the group (a commit it applied removed
    /// it, or a Welcome that brought this device back left them out) is
    /// [`JoinRequestVerdict::NotAMember`] whatever `pending_actors` says,
    /// until they hold a leaf again or this device's person leaves the group
    /// on purpose ([`Self::forget_remembered_roster`] drops the record). A caller that
    /// names the asker out of habit therefore cannot hand an ex-member a seat
    /// while the record lasts. A person this device
    /// has itself decided to admit by its own rule (a group link it approved,
    /// an open group's join inbox) is checked with
    /// [`Self::verify_admitted_join_request`] instead, which says so.
    ///
    /// A device that holds no copy of `group_id` judges everyone but its own
    /// person and `pending_actors` as not a member.
    ///
    /// Like every read, it answers from the groups as this client last loaded
    /// them. On a store another process also writes
    /// (`docs/mls-core.md` §A store two processes share), call
    /// [`Self::refresh_if_moved`] first, or a member that process just
    /// removed still holds a leaf here. The C door does this itself.
    pub fn verify_join_request(
        &self,
        group_id: &[u8],
        actor_id: &str,
        device_id: &str,
        proof: &[u8],
        key_package: &[u8],
        pending_actors: &[&str],
    ) -> JoinRequestVerdict {
        let verdict =
            self.verify_join_request_proof(group_id, actor_id, device_id, proof, key_package);
        if !verdict.is_accepted() {
            return verdict;
        }
        self.join_request_membership(group_id, actor_id, device_id, key_package, pending_actors)
    }

    /// The last step of [`Self::verify_join_request`]: whether the asker
    /// belongs, judged on the groups as this client holds them now. Read by
    /// [`Self::add_member_for_ask`] again on the store its add commits on.
    fn join_request_membership(
        &self,
        group_id: &[u8],
        actor_id: &str,
        device_id: &str,
        key_package: &[u8],
        pending_actors: &[&str],
    ) -> JoinRequestVerdict {
        // A device of this account that the account removed is a member of
        // nothing, by its id or under any key it was seen holding, whatever
        // else the ask proves: its own person's seat is not its seat.
        if actor_id == self.identity.actor_id {
            let forgotten = match self.key_package_identity(key_package) {
                Ok(Ok(identity)) => {
                    self.is_forgotten_own_device(&identity.device_id, &identity.device_key)
                }
                _ => true,
            };
            if forgotten || self.is_forgotten_own_device(device_id, &[]) {
                return JoinRequestVerdict::NotAMember;
            }
        }
        if actor_id == self.identity.actor_id
            || self.holds_leaf_of_actor(group_id, actor_id)
            || (pending_actors.contains(&actor_id) && !self.saw_depart(group_id, actor_id))
        {
            JoinRequestVerdict::Accepted
        } else {
            JoinRequestVerdict::NotAMember
        }
    }

    /// Whether `(actor_id, device_id)`'s signed request to be seated in
    /// `group_id` holds, for a person this device has ITSELF decided to
    /// admit by its own rule: somebody who asked through a group link this
    /// device approved, or through an open group's join inbox, which seats
    /// whoever asks. Every check of [`Self::verify_join_request`] but the last:
    /// the credential, the identity, the signature and the clock. Membership
    /// is not judged, because the caller's rule already decided it; that is
    /// also what lets a person who left come back through a link or an inbox.
    ///
    /// Never called on a rejoin's seat ask (envelope kind 3): that ask claims
    /// a seat the asker already holds, and only
    /// [`Self::verify_join_request`] judges that claim. Never fails.
    pub fn verify_admitted_join_request(
        &self,
        group_id: &[u8],
        actor_id: &str,
        device_id: &str,
        proof: &[u8],
        key_package: &[u8],
    ) -> JoinRequestVerdict {
        self.verify_join_request_proof(group_id, actor_id, device_id, proof, key_package)
    }

    /// The checks both seat-ask doors share: the key package's credential,
    /// then [`crate::join_request::check_join_request`] at this client's clock.
    fn verify_join_request_proof(
        &self,
        group_id: &[u8],
        actor_id: &str,
        device_id: &str,
        proof: &[u8],
        key_package: &[u8],
    ) -> JoinRequestVerdict {
        let identity = match self.key_package_identity(key_package) {
            Ok(Ok(identity)) => identity,
            Ok(Err(_)) | Err(_) => return JoinRequestVerdict::CredentialRejected,
        };
        crate::join_request::check_join_request(
            &identity,
            group_id,
            actor_id,
            device_id,
            proof,
            self.identity_provider.now_unix(),
        )
    }

    /// Whether this device saw `actor_id`'s last leaf leave `group_id`
    /// (`NS_DEPARTED` in [`crate::storage`]). A store that cannot answer
    /// answers yes: the caller's pending list is then not honoured for this
    /// ask, and the asker's next ask is judged again.
    fn saw_depart(&self, group_id: &[u8], actor_id: &str) -> bool {
        self.provider
            .peachy_storage()
            .departed(group_id, actor_id)
            .unwrap_or(true)
    }

    /// The actors of `leaves` in `group`, read with every credential check
    /// but the clock, this device's own person left out. Read BEFORE a commit
    /// that removes them is merged.
    fn actors_at_leaves(
        identity_provider: &PeachyIdentityProvider,
        own_actor: &str,
        group: &MlsGroup,
        leaves: &[u32],
    ) -> Vec<String> {
        let mut actors: Vec<String> = Vec::new();
        for member in group.members() {
            if !leaves.contains(&member.index.u32()) {
                continue;
            }
            let Ok((identity, _)) = identity_provider.validate_seated_credential(
                &member.credential,
                &member.signature_key,
                i64::MAX,
            ) else {
                continue;
            };
            if identity.actor_id != own_actor && !actors.contains(&identity.actor_id) {
                actors.push(identity.actor_id);
            }
        }
        actors
    }

    /// The `(device_id, device_key)` of this account's OTHER devices at
    /// `leaves` in `group`, read with every credential check but the clock.
    /// Read BEFORE a commit that removes them is merged.
    fn own_siblings_at_leaves(
        identity_provider: &PeachyIdentityProvider,
        me: &PeachyIdentity,
        group: &MlsGroup,
        leaves: &[u32],
    ) -> Vec<(String, Vec<u8>)> {
        if leaves.is_empty() {
            return Vec::new();
        }
        group
            .members()
            .filter(|member| leaves.contains(&member.index.u32()))
            .filter_map(|member| {
                identity_provider
                    .validate_seated_credential(&member.credential, &member.signature_key, i64::MAX)
                    .ok()
            })
            .map(|(identity, _)| identity)
            .filter(|identity| {
                identity.actor_id == me.actor_id && identity.device_id != me.device_id
            })
            .map(|identity| (identity.device_id, identity.device_key.to_vec()))
            .collect()
    }

    /// The `(device_id, device_key)` of each leaf of this account's other
    /// devices that `added` seats under a device id one of `removed_siblings`
    /// held under another key: what a receiver has not already refused as a
    /// reseat under another device key (`rekeys_a_removed_seat`), a seat under
    /// another account key, vouches for nothing.
    fn rekeyed_own_seats(
        removed_siblings: &[(String, Vec<u8>)],
        me: &PeachyIdentity,
        added: &[PeachyIdentity],
    ) -> Vec<(String, Vec<u8>)> {
        added
            .iter()
            .filter(|leaf| leaf.actor_id == me.actor_id && leaf.device_id != me.device_id)
            .map(|leaf| (leaf.device_id.clone(), leaf.device_key.to_vec()))
            .filter(|(id, key)| {
                removed_siblings
                    .iter()
                    .any(|(old_id, old_key)| old_id == id && old_key != key)
            })
            .collect()
    }

    /// Whether a commit that removes `removed` and adds `added` leaves two
    /// leaves of `group` under one device id: an added leaf whose id a kept
    /// leaf carries, or two added leaves of one id.
    fn seats_a_second_leaf(
        identity_provider: &PeachyIdentityProvider,
        group: &MlsGroup,
        removed: &[u32],
        added: &[PeachyIdentity],
    ) -> bool {
        let mut ids: Vec<String> = group
            .members()
            .filter(|member| !removed.contains(&member.index.u32()))
            .filter_map(|member| {
                identity_provider
                    .validate_seated_credential(&member.credential, &member.signature_key, i64::MAX)
                    .ok()
            })
            .map(|(identity, _)| identity.device_id)
            .collect();
        for leaf in added {
            if ids.contains(&leaf.device_id) {
                return true;
            }
            ids.push(leaf.device_id.clone());
        }
        false
    }

    /// Whether a commit that removes `removed` and adds `added` gives one of
    /// the seats it takes out back under another device key: the same actor,
    /// device id and account key as a removed leaf, under a device key that
    /// leaf did not carry. Refused by every receiver.
    fn rekeys_a_removed_seat(
        identity_provider: &PeachyIdentityProvider,
        group: &MlsGroup,
        removed: &[u32],
        added: &[PeachyIdentity],
    ) -> bool {
        group
            .members()
            .filter(|member| removed.contains(&member.index.u32()))
            .filter_map(|member| {
                identity_provider
                    .validate_seated_credential(&member.credential, &member.signature_key, i64::MAX)
                    .ok()
            })
            .any(|(gone, _)| {
                added.iter().any(|leaf| {
                    leaf.actor_id == gone.actor_id
                        && leaf.device_id == gone.device_id
                        && leaf.account_key == gone.account_key
                        && leaf.device_key != gone.device_key
                })
            })
    }

    /// The people a staged commit takes out because they LEFT: each person
    /// every one of whose identified leaves in `group` is the target of a
    /// Remove named by reference (which the rules take only as a leave) that
    /// one of that person's own leaves proposed. A person any of whose leaves
    /// goes by an inline Remove was removed by the committer, not left. Read
    /// BEFORE the commit is merged. Sorted.
    fn leavers(
        identity_provider: &PeachyIdentityProvider,
        group: &MlsGroup,
        staged: &openmls::prelude::StagedCommit,
    ) -> Vec<String> {
        let seated: Vec<(u32, String)> = group
            .members()
            .filter_map(|member| {
                identity_provider
                    .validate_seated_credential(&member.credential, &member.signature_key, i64::MAX)
                    .ok()
                    .map(|(identity, _)| (member.index.u32(), identity.actor_id))
            })
            .collect();
        let actor_at = |leaf: u32| {
            seated
                .iter()
                .find(|(index, _)| *index == leaf)
                .map(|(_, actor)| actor)
        };
        // The leaves a by-reference Remove takes out, each its proposer's own.
        let left_leaves: Vec<u32> = staged
            .queued_proposals()
            .filter(|queued| {
                queued.proposal_or_ref_type() == openmls::prelude::ProposalOrRefType::Reference
            })
            .filter_map(|queued| match (queued.proposal(), queued.sender()) {
                (
                    openmls::prelude::Proposal::Remove(remove),
                    openmls::prelude::Sender::Member(sender),
                ) => {
                    let target = remove.removed().u32();
                    let own =
                        actor_at(target).is_some() && actor_at(target) == actor_at(sender.u32());
                    own.then_some(target)
                }
                _ => None,
            })
            .collect();
        let mut left: Vec<String> = Vec::new();
        for (index, actor) in &seated {
            if !left_leaves.contains(index) || left.contains(actor) {
                continue;
            }
            let gone = seated
                .iter()
                .filter(|(_, other)| other == actor)
                .all(|(leaf, _)| left_leaves.contains(leaf));
            if gone {
                left.push(actor.clone());
            }
        }
        left.sort();
        left
    }

    /// Of `actors`, those who hold no leaf in `group` as it stands now.
    fn without_a_leaf(
        identity_provider: &PeachyIdentityProvider,
        group: &MlsGroup,
        mut actors: Vec<String>,
    ) -> Vec<String> {
        if actors.is_empty() {
            return actors;
        }
        for member in group.members() {
            if let Ok((identity, _)) = identity_provider.validate_seated_credential(
                &member.credential,
                &member.signature_key,
                i64::MAX,
            ) {
                actors.retain(|actor| *actor != identity.actor_id);
            }
        }
        actors
    }

    /// Record that each of `actors` left `group_id` (`NS_DEPARTED`).
    fn note_departed(&self, group_id: &[u8], actors: &[String]) -> Result<()> {
        for actor in actors {
            self.provider
                .peachy_storage()
                .set_departed(group_id, actor)?;
        }
        Ok(())
    }

    /// Drop the departed record (`NS_DEPARTED`) of every actor holding a
    /// leaf in the copy of `group_id` held now, credentials read with every
    /// check but the clock: a person seated again has not left. Called when
    /// a seat is taken and before a copy's people are kept (a merged commit
    /// clears the people it adds), so a stale record, one never cleared
    /// included, never leaves a member out of a rejoin report or vetoes
    /// their seat ask.
    fn clear_departed_of_seated(&self, group_id: &[u8]) -> Result<()> {
        let Some(group) = self.groups.get(group_id) else {
            return Ok(());
        };
        let storage = self.provider.peachy_storage();
        for member in group.members() {
            if let Ok((identity, _)) = self.identity_provider.validate_seated_credential(
                &member.credential,
                &member.signature_key,
                i64::MAX,
            ) {
                storage.clear_departed(group_id, &identity.actor_id)?;
            }
        }
        Ok(())
    }

    /// Whether any leaf of `group_id` as this device holds it belongs to
    /// `actor_id`, its credential parsed without verifying it
    /// ([`PeachyIdentityProvider::claimed_person`]), so a seated person whose
    /// credential no longer verifies today still counts as seated. False
    /// for a group this device does not hold.
    fn holds_leaf_of_actor(&self, group_id: &[u8], actor_id: &str) -> bool {
        let Some(group) = self.groups.get(group_id) else {
            return false;
        };
        group.members().any(|member| {
            PeachyIdentityProvider::claimed_person(&member.credential)
                .is_some_and(|(actor, _, _)| actor == actor_id)
        })
    }

    /// Whether this device is seeing a signed seat ask for `group_id` for the
    /// first time, and if so, a record that it has. Asked when the ask is
    /// TAKEN IN: when it arrives in the mailbox (envelope kind 3), or when a
    /// join inbox's ask is acted on; [`Self::verify_join_request`] is still
    /// what decides whether it holds, as often as the caller needs to ask
    /// that, and [`Self::join_request_seen`] asks without keeping a record.
    ///
    /// A proof is good for [`crate::join_request::JOIN_REQUEST_MAX_AGE_SECONDS`]
    /// after it was signed, and the delivery service, which carries it, can
    /// deliver the same bytes again inside that day. Each delivery would make
    /// a member seat the asking device again — replacing a leaf that may be
    /// healthy, and costing the device what was said while it waited for the
    /// Welcome. So the ask's nonce is kept, under the group, until the ask is
    /// too old to verify, and the same ask arriving again answers false: the
    /// caller drops it.
    ///
    /// Per device: a delivery service that withheld an ask from one member's
    /// device can still hand it to that device once. False for a proof that
    /// does not parse (it seats nobody either). A proof already stale, or
    /// from too far ahead, answers true and is not kept; the verdict refuses
    /// it.
    ///
    /// The record is the ask's signature as well as its nonce: an ask
    /// somebody else signed with a nonce they learned (from a server, or as
    /// a member reading the same envelope) is another ask, and taking it in
    /// first does not make the genuine one look like a repeat. Under the
    /// store's write lock, so two processes on one store cannot both take in
    /// the same ask.
    pub fn first_sight_of_join_request(&mut self, group_id: &[u8], proof: &[u8]) -> Result<bool> {
        self.synced(|client| {
            let Some((key, issued_at)) = client.join_request_record(group_id, proof)? else {
                return Ok(false);
            };
            let Some(key) = key else {
                return Ok(true);
            };
            let storage = client.provider.peachy_storage();
            if storage.join_request_seen(&key)? {
                return Ok(false);
            }
            storage.note_join_request(&key, issued_at)?;
            Ok(true)
        })
    }

    /// Whether this device has already taken in this signed seat ask for
    /// `group_id` ([`Self::first_sight_of_join_request`]), keeping no record.
    /// For an ask that waits where the delivery service keeps it (a join
    /// inbox) and is read again on every pass until somebody acts on it. False
    /// for a proof that does not parse, is stale or is from too far ahead.
    /// It prunes aged-out records on the way, as one step against the store,
    /// closed before it returns.
    pub fn join_request_seen(&mut self, group_id: &[u8], proof: &[u8]) -> Result<bool> {
        self.synced(
            |client| match client.join_request_record(group_id, proof)? {
                Some((Some(key), _)) => {
                    Ok(client.provider.peachy_storage().join_request_seen(&key)?)
                }
                _ => Ok(false),
            },
        )
    }

    /// The record key and signing time of a seat ask: `None` for a proof that
    /// does not parse, a `None` key for one outside the window it could
    /// verify in. Prunes records that have aged out on the way.
    ///
    /// The key is the SHA-256 of the group id, then the nonce, then the
    /// signature: the signer's own mark on the ask, so only the same signed
    /// ask matches it. The signature verifies strictly
    /// (`join_request::verify_join_request_signature`), so a delivery service
    /// cannot re-encode the same ask under another signature either.
    fn join_request_record(
        &self,
        group_id: &[u8],
        proof: &[u8],
    ) -> Result<Option<(Option<Vec<u8>>, i64)>> {
        use crate::join_request::{JOIN_REQUEST_FUTURE_SKEW_SECONDS, JOIN_REQUEST_MAX_AGE_SECONDS};
        let Some((issued_at, nonce, signature)) = crate::join_request::join_request_parts(proof)
        else {
            return Ok(None);
        };
        let now = self.identity_provider.now_unix();
        let oldest = now.saturating_sub(JOIN_REQUEST_MAX_AGE_SECONDS);
        self.provider.peachy_storage().prune_join_requests(oldest)?;
        if issued_at < oldest || issued_at > now.saturating_add(JOIN_REQUEST_FUTURE_SKEW_SECONDS) {
            return Ok(Some((None, issued_at)));
        }
        let mut key: Vec<u8> = sha2::Sha256::digest(group_id).to_vec();
        key.extend_from_slice(&nonce);
        key.extend_from_slice(&signature);
        Ok(Some((Some(key), issued_at)))
    }

    /// The current epoch.
    pub fn epoch(&self, group_id: &[u8]) -> Result<u64> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        Ok(group.epoch().as_u64())
    }

    /// This device's own leaf in `group_id`.
    pub(crate) fn own_leaf(&self, group_id: &[u8]) -> Result<u32> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        Ok(group.own_leaf_index().u32())
    }

    /// Sign `statement` with this device's leaf key: the same Ed25519 key its
    /// credential binds and its MLS messages are signed with. For statements
    /// under a domain of their own (`crate::typing`), never MLS content.
    pub(crate) fn sign_with_own_leaf(&self, statement: &[u8]) -> Result<Vec<u8>> {
        openmls_traits::signatures::Signer::sign(&self.signer, statement)
            .map_err(|err| Error::Mls(format!("could not sign with the leaf key: {err:?}")))
    }

    /// Every leaf of `actor_id` in `group_id` whose credential checks out
    /// (within the expired-leaf grace, as [`Self::roster`] reads them), with
    /// its signature key: who may have signed a statement that names this
    /// person (`crate::typing`).
    pub(crate) fn leaf_keys_of_actor(
        &self,
        group_id: &[u8],
        actor_id: &str,
    ) -> Result<Vec<(u32, Vec<u8>)>> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        Ok(group
            .members()
            .filter(|member| {
                self.identity_provider
                    .validate_seated_credential(
                        &member.credential,
                        &member.signature_key,
                        crate::identity::EXPIRED_LEAF_GRACE_SECONDS,
                    )
                    .is_ok_and(|(identity, _)| identity.actor_id == actor_id)
            })
            .map(|member| (member.index.u32(), member.signature_key.clone()))
            .collect())
    }

    /// Unix milliseconds on the clock devices agree on: this client's clock
    /// plus the server's offset ([`crate::set_server_clock_offset_ms`]). What
    /// the live call lane and typing stamp and judge each other's frames by,
    /// so a device whose own clock is off still agrees with its peers.
    pub(crate) fn now_unix_ms(&self) -> u64 {
        let local = self.identity_provider.now_unix_ms();
        u64::try_from(local.saturating_add(crate::identity::server_clock_offset_ms())).unwrap_or(0)
    }

    /// Unix seconds on THIS DEVICE's own clock, with no server offset: what
    /// every credential verdict is made on (`crate::identity`).
    pub(crate) fn device_now_unix(&self) -> i64 {
        self.identity_provider.now_unix()
    }

    /// What `crate::revocation::stale_leaf_removable` needs from the group
    /// beyond its roster: the group's tree clock ([`Self::tree_clock`]), and,
    /// for a leaf still seated from its key package, when its own device
    /// minted that package (the window's start, which the device signs, plus
    /// the hour it backdates by), or `None` once the leaf has been renewed.
    pub(crate) fn stale_leaf_group_clock(
        &self,
        group_id: &[u8],
        leaf_index: u32,
    ) -> Result<(i64, Option<i64>)> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        let minted_at = group
            .public_group()
            .leaf(LeafNodeIndex::new(leaf_index))
            .and_then(|leaf| match leaf.leaf_node_source() {
                openmls::treesync::LeafNodeSource::KeyPackage(lifetime) => {
                    i64::try_from(lifetime.not_before()).ok().map(|start| {
                        start.saturating_add(
                            i64::try_from(crate::key_package_lifetime::MINT_BACKDATE_SECONDS)
                                .unwrap_or(0),
                        )
                    })
                }
                _ => None,
            });
        Ok((Self::tree_clock(group, None), minted_at))
    }

    /// [`Self::stale_leaf_group_clock`], for a test that checks what a stale
    /// leaf's verdict is judged on. Test-only; see `test-forgery` in
    /// Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn stale_leaf_clock_for_test(
        &self,
        group_id: &[u8],
        leaf_index: u32,
    ) -> Result<(i64, Option<i64>)> {
        self.stale_leaf_group_clock(group_id, leaf_index)
    }

    /// Milliseconds on this client's monotonic clock ([`Clock::monotonic_ms`]):
    /// for a span this device measures alone, which setting the wall clock
    /// must not move.
    pub(crate) fn now_monotonic_ms(&self) -> u64 {
        self.identity_provider.monotonic_ms()
    }

    /// Whether this client is still an active member.
    pub fn is_active(&self, group_id: &[u8]) -> Result<bool> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        Ok(group.is_active())
    }

    // ---- Membership ---------------------------------------------------------

    /// Add a member from their published key package.
    ///
    /// The key package is validated cryptographically by OpenMLS and then by
    /// [`PeachyIdentityProvider`] — in that order, because a key package whose
    /// own signature does not check out has no credential worth reading.
    pub fn add_member(&mut self, group_id: &[u8], key_package: &[u8]) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome = client.stage_add_member(group_id, key_package);
            client.stage_committed(group_id, outcome)
        })
    }

    /// [`Self::add_member`] for a rejoin's seat ask (envelope kind 3) whose
    /// device holds no leaf: the add a member makes after
    /// [`Self::verify_join_request`] accepted the ask. That verdict was read
    /// before the package fetch awaited; here its membership step is judged
    /// again, with the same `pending_actors`, on the store this add commits
    /// on and under the same write lock, so a removal of the asker's person
    /// that another process applied in between, or a departure this device
    /// saw meanwhile, refuses the add instead of putting the person back.
    /// The asker is the person and device the package's credential names,
    /// which the proof was checked against. Anything but
    /// [`JoinRequestVerdict::Accepted`] is [`Error::InvalidArgument`] naming
    /// the verdict, and nothing is staged.
    pub fn add_member_for_ask(
        &mut self,
        group_id: &[u8],
        key_package: &[u8],
        pending_actors: &[&str],
    ) -> Result<CommitBundle> {
        self.synced(|client| {
            let (_, joining) = client.validated_key_package(key_package)?;
            let verdict = client.join_request_membership(
                group_id,
                &joining.actor_id,
                &joining.device_id,
                key_package,
                pending_actors,
            );
            if !verdict.is_accepted() {
                return Err(Error::invalid(format!(
                    "that seat ask no longer holds: {}",
                    verdict.name()
                )));
            }
            let outcome = client.stage_add_member(group_id, key_package);
            client.stage_committed(group_id, outcome)
        })
    }

    fn stage_add_member(&mut self, group_id: &[u8], key_package: &[u8]) -> Result<CommitBundle> {
        let (key_package, joining) = self.validated_key_package(key_package)?;
        self.refuse_if_forgotten_own_device(&joining)?;
        self.rules
            .evaluate(&self.own_context(ProposalKind::Add))
            .into_result()?;

        if !self
            .groups
            .get(group_id)
            .ok_or(Error::NoSuchGroup)?
            .is_active()
        {
            return Err(Error::NotAMember);
        }
        self.refuse_if_device_seated(group_id, &joining, None)?;
        self.refuse_if_own_leaf_lapsed(group_id)?;
        self.refuse_if_commit_staged(group_id)?;
        // The proposal store is NOT consumed, by this or any commit this
        // client builds: a commit carries exactly the change asked for, all of
        // it inline and all of it this member's, so nothing another member
        // queued can ride into it (`crate::rules` §Why proposals by reference
        // are refused). The update path is forced, as OpenMLS's own add does.
        let plan = CommitPlan {
            adds: 1,
            proposals_len: CommitPlan::inline_proposal(key_package.tls_serialized_len()),
            ..CommitPlan::default()
        };
        let trees = self.welcome_trees_for(group_id, &plan, [&key_package])?;
        let bundle = self.padded_commit(group_id, &plan, |this| {
            let provider = &this.provider;
            let signer = &this.signer;
            let group = this.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            group
                .commit_builder()
                .consume_proposal_store(false)
                .propose_adds([key_package])
                .force_self_update(true)
                .load_psks(provider.storage())
                .map_err(mls_err)?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(mls_err)?
                .stage_commit(provider)
                .map_err(mls_err)
        })?;
        self.refuse_own_commit_receivers_would_refuse(group_id)?;
        let commit = bundle.commit().to_bytes().map_err(mls_err)?;
        let welcome = self
            .welcome_out(&trees, &bundle, None, None)?
            .ok_or_else(|| Error::Mls("an add staged no Welcome".into()))?;
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;

        // STAGED, NOT MERGED. See §The commit lifecycle.
        Ok(CommitBundle {
            commit,
            welcome: Some(welcome),
            epoch: group.epoch().as_u64() + 1,
        })
    }

    /// A KeyPackage, checked as an add checks it: by OpenMLS, then by
    /// [`PeachyIdentityProvider`], then its lifetime as the adder judges it
    /// (`crate::key_package_lifetime::check_at_adder`).
    fn validated_key_package(&self, key_package: &[u8]) -> Result<(KeyPackage, PeachyIdentity)> {
        let message = MlsMessageIn::tls_deserialize_exact(key_package)?;
        let MlsMessageBodyIn::KeyPackage(incoming) = message.extract() else {
            return Err(Error::invalid("that message is not a KeyPackage"));
        };
        let key_package = Self::adder_checked(&self.provider, &self.identity_provider, incoming)?;
        let identity = self.identity_provider.validate_key_package(&key_package)?;
        Ok((key_package, identity))
    }

    /// OpenMLS's checks of a KeyPackage (among them that its window has
    /// started and not ended, on this device's clock), then its lifetime as
    /// the adder judges it, on the core's clock. A credential the strict check refuses
    /// leaves the verdict to that check, run after this, so a credential's
    /// own rejection (not yet valid, expired) is the one named.
    fn adder_checked(
        provider: &PeachyProvider,
        identity_provider: &PeachyIdentityProvider,
        incoming: openmls::prelude::KeyPackageIn,
    ) -> Result<KeyPackage> {
        let key_package = incoming
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls_err)?;
        if identity_provider.validate_key_package(&key_package).is_ok() {
            crate::key_package_lifetime::check_at_adder(
                &key_package,
                identity_provider.now_unix(),
            )?;
        }
        Ok(key_package)
    }

    /// THE PACKAGES A FOUNDING LEAVES OUT: the index in `key_packages` of
    /// each one [`Self::seat_founding`] would refuse, ascending. It changes
    /// nothing stored, and it needs only the group of one
    /// [`Self::create_group`] made, so a client runs it before it opens the
    /// conversation at the server. A founding drops these and seats
    /// everybody else in its one commit; their devices are offered ordinary
    /// adds once it is merged, whose set is then the whole tree. A founding
    /// meant to seat another person, some of whose packages came back and
    /// all of them are dropped, fails there, before anything is sent, rather
    /// than seat only the founder's own devices; one with no other person's
    /// package at all goes on with hers (docs/delivery.md §Founding
    /// a conversation).
    ///
    /// No package can refuse the founding of everybody else: one the MLS
    /// commit itself would refuse is named here too. Past the checks of
    /// [`Self::founding_checks`], the founding commit of every package that
    /// passed is built, never staged, and only if MLS refuses that build is
    /// each package tried on its own, first come first seated, so an honest
    /// founding pays for one build.
    ///
    /// A package the build refuses is then left out of the checks too, and
    /// they run again, until a round leaves out nothing new: a package MLS
    /// refuses claims no device id and no account key ahead of a later
    /// package of the same device or person, as it would if it were seated.
    /// Each round leaves out at least one more package, so the rounds end.
    pub fn founding_refusals(
        &mut self,
        group_id: &[u8],
        key_packages: &[Vec<u8>],
    ) -> Result<Vec<u32>> {
        let mut excluded: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        loop {
            let (joining, refused) = self.founding_checks(group_id, key_packages, &excluded)?;
            let passed: Vec<KeyPackage> = joining.iter().map(|(_, _, kp)| kp.clone()).collect();
            let mut built_out = Vec::new();
            if !passed.is_empty() && self.build_founding_commit(group_id, passed).is_err() {
                let mut seated: Vec<KeyPackage> = Vec::with_capacity(joining.len());
                for (index, _, key_package) in joining {
                    let mut trial = seated.clone();
                    trial.push(key_package.clone());
                    match self.build_founding_commit(group_id, trial) {
                        Ok(()) => seated.push(key_package),
                        Err(_) => built_out.push(index),
                    }
                }
            }
            if built_out.is_empty() {
                let mut indices: Vec<u32> = refused.into_iter().map(|(index, _)| index).collect();
                indices.sort_unstable();
                return Ok(indices);
            }
            excluded.extend(built_out);
        }
    }

    /// Build the commit [`Self::stage_founding`] builds, the same chain on
    /// the same group, and drop it: never staged, nothing stored. OpenMLS
    /// keeps its own checks of the adds (cipher suite and version, leaf
    /// capabilities, unique keys, leaf lifetime) inside its builder, so
    /// building is how they are asked; `Err` is what they refused.
    fn build_founding_commit(&mut self, group_id: &[u8], joining: Vec<KeyPackage>) -> Result<()> {
        let provider = &self.provider;
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        group
            .commit_builder()
            .consume_proposal_store(false)
            .propose_adds(joining)
            .force_self_update(true)
            .load_psks(provider.storage())
            .map_err(mls_err)?
            .build(provider.rand(), provider.crypto(), &self.signer, |_| true)
            .map_err(mls_err)?;
        Ok(())
    }

    /// The one list of a founding's per-package checks, which
    /// [`Self::founding_refusals`] and [`Self::seat_founding`] both read: a
    /// package is checked as an add checks it, refused when its leaf does
    /// not list the group-state extension (every conversation carries it
    /// from its state commit on, but the group of one this is first read on
    /// carries none yet, so the commit's own check could not see it there),
    /// refused when it is a device this account forgot as removed
    /// ([`Self::refuse_if_forgotten_own_device`], as at every add), refused
    /// when its device already holds a leaf of the tree before the
    /// commit, refused when an earlier package of the same founding that
    /// passed carries its device id (one device, one leaf, as
    /// [`Self::add_member`] holds it one commit at a time), and refused when
    /// it would put one person under two account keys
    /// (`crate::policy::judge_account_keys`, the rule the commit is judged
    /// by), against this device's leaf and the packages that passed before
    /// it. First come, first seated, in both rules. The MLS commit's own
    /// checks come after these: built in [`Self::founding_refusals`], and
    /// by the founding commit itself in [`Self::seat_founding`]. A package
    /// whose index is in `excluded` (one that commit refused) is refused
    /// first, before it can claim anything.
    fn founding_checks(
        &self,
        group_id: &[u8],
        key_packages: &[Vec<u8>],
        excluded: &std::collections::BTreeSet<u32>,
    ) -> Result<FoundingSort> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        let mut joining: Vec<(u32, String, KeyPackage)> = Vec::with_capacity(key_packages.len());
        let mut refused = Vec::new();
        // The tree before the commit, read as the commit's own account-key
        // check reads it, then each package that passes.
        let mut kept: Vec<crate::policy::Seat> = group
            .members()
            .filter_map(|member| {
                self.identity_provider
                    .validate_seated_credential(&member.credential, &member.signature_key, i64::MAX)
                    .ok()
            })
            .map(|(identity, _)| Self::seat_of(identity))
            .collect();
        let reader = self
            .identity
            .account_key
            .as_ref()
            .map(|key| (self.identity.actor_id.as_str(), key));
        for (index, bytes) in key_packages.iter().enumerate() {
            let index = u32::try_from(index)
                .map_err(|_| Error::invalid("too many KeyPackages for one founding"))?;
            if excluded.contains(&index) {
                refused.push((
                    index,
                    Error::invalid("the founding commit refuses that package"),
                ));
                continue;
            }
            let checked = self
                .validated_key_package(bytes)
                .and_then(|(key_package, identity)| {
                    if !key_package
                        .leaf_node()
                        .capabilities()
                        .extensions()
                        .contains(&group_meta_extension_type())
                    {
                        return Err(Error::invalid(
                            "that device's leaf cannot carry the conversation's state",
                        ));
                    }
                    self.refuse_if_forgotten_own_device(&identity)?;
                    self.refuse_if_device_seated(group_id, &identity, None)?;
                    if joining
                        .iter()
                        .any(|(_, device, _)| *device == identity.device_id)
                    {
                        return Err(Error::invalid(
                            "that device is seated by another package of this founding",
                        ));
                    }
                    let device_id = identity.device_id.clone();
                    let seat = Self::seat_of(identity);
                    if let PolicyDecision::Deny(reason) = crate::policy::judge_account_keys(
                        reader,
                        &kept,
                        std::slice::from_ref(&seat),
                    ) {
                        return Err(Error::PolicyRefused(reason));
                    }
                    Ok((key_package, seat, device_id))
                });
            match checked {
                Ok((key_package, seat, device_id)) => {
                    kept.push(seat);
                    joining.push((index, device_id, key_package));
                }
                Err(why) => refused.push((index, why)),
            }
        }
        Ok((joining, refused))
    }

    /// SEAT EVERYBODY AT A FOUNDING, IN ONE COMMIT THAT NAMES NOBODY
    /// (crate::founding; docs/delivery.md §Founding a conversation).
    ///
    /// One commit adds every device in `key_packages`, and its one Welcome
    /// also carries a seat sealed to `own_key_package`, a KeyPackage of THIS
    /// device that the founding fetched the way it fetched everyone else's.
    /// The caller sends the same Welcome to every device it adds and to this
    /// one, in device-id order, and submits the commit with no recipients:
    /// the tree before it is this device's alone. The devices take their
    /// leaves in an order drawn at random, whatever order `key_packages` is
    /// in.
    ///
    /// Only in a group whose one leaf is this device, with at most
    /// [`crate::founding::FOUNDING_MAX_SEATS`] devices in all; refused
    /// otherwise. A package [`Self::founding_refusals`] names refuses the
    /// whole founding: the caller leaves those out and seats their devices
    /// by ordinary adds once this commit is merged, and never falls back to
    /// one add per commit. This device's own package, a one-time one, has
    /// its private half erased here: nothing may open the copy of the
    /// Welcome sent to this device.
    ///
    /// **Staged, not merged**, like every other commit here.
    pub fn seat_founding(
        &mut self,
        group_id: &[u8],
        key_packages: &[Vec<u8>],
        own_key_package: &[u8],
    ) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome = client.stage_founding(group_id, key_packages, own_key_package);
            client.stage_committed(group_id, outcome)
        })
    }

    /// Put a founding's joiners in a uniformly random order (Fisher-Yates,
    /// a 64-bit draw per place from the provider's CSPRNG; the bias of
    /// reducing one modulo at most 32 is below 2^-58).
    fn shuffle_seats<T>(&self, seats: &mut [T]) -> Result<()> {
        use openmls_traits::random::OpenMlsRand as _;
        let draws = self
            .provider
            .rand()
            .random_vec(8 * seats.len())
            .map_err(|_| Error::Mls("no randomness for a founding's seating order".into()))?;
        let (words, _) = draws.as_chunks::<8>();
        for (place, word) in words.iter().enumerate().skip(1).rev() {
            let word = u64::from_be_bytes(*word);
            let span = u64::try_from(place).unwrap_or(u64::MAX).saturating_add(1);
            let pick = usize::try_from(word % span).unwrap_or(0);
            seats.swap(place, pick);
        }
        Ok(())
    }

    fn stage_founding(
        &mut self,
        group_id: &[u8],
        key_packages: &[Vec<u8>],
        own_key_package: &[u8],
    ) -> Result<CommitBundle> {
        {
            let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
            if !group.is_active() {
                return Err(Error::NotAMember);
            }
            if group.members().count() != 1 {
                return Err(Error::invalid(
                    "a founding seats a group whose only leaf is this device",
                ));
            }
        }
        if key_packages.is_empty() {
            return Err(Error::invalid("a founding seats at least one other device"));
        }
        if key_packages.len() >= crate::founding::FOUNDING_MAX_SEATS {
            return Err(Error::invalid(
                "a founding commit seats at most 32 devices, the founder's included",
            ));
        }
        self.rules
            .evaluate(&self.own_context(ProposalKind::Add))
            .into_result()?;
        self.refuse_if_own_leaf_lapsed(group_id)?;
        self.refuse_if_commit_staged(group_id)?;

        let (own, own_identity) = self.validated_key_package(own_key_package)?;
        if own_identity.device_id != self.identity.device_id
            || own_identity.device_key != self.identity.device_key
        {
            return Err(Error::invalid(
                "the founder's seat is a KeyPackage of this device",
            ));
        }
        let (mut joining, refused) =
            self.founding_checks(group_id, key_packages, &std::collections::BTreeSet::new())?;
        if let Some((_, why)) = refused.into_iter().next() {
            return Err(why);
        }
        // Seated in an order drawn at random, neither the order the caller
        // passed them nor one the server could work out (device ids): the
        // leaves the joiners take hold no choice of the founder's
        // (docs/delivery.md §Founding a conversation).
        self.shuffle_seats(&mut joining)?;
        let joining: Vec<KeyPackage> = joining
            .into_iter()
            .map(|(_, _, key_package)| key_package)
            .collect();
        let proposals_len = joining
            .iter()
            .map(|key_package| CommitPlan::inline_proposal(key_package.tls_serialized_len()))
            .sum();
        let plan = CommitPlan {
            adds: joining.len(),
            proposals_len,
            ..CommitPlan::default()
        };
        let trees = self.welcome_trees_for(group_id, &plan, joining.iter())?;
        let bundle = self.padded_commit(group_id, &plan, |this| {
            let provider = &this.provider;
            let signer = &this.signer;
            let group = this.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            group
                .commit_builder()
                .consume_proposal_store(false)
                .propose_adds(joining)
                .force_self_update(true)
                .load_psks(provider.storage())
                .map_err(mls_err)?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(mls_err)?
                .stage_commit(provider)
                .map_err(mls_err)
        })?;
        self.refuse_own_commit_receivers_would_refuse(group_id)?;
        let commit = bundle.commit().to_bytes().map_err(mls_err)?;
        let welcome = self
            .welcome_out(&trees, &bundle, Some(&own), None)?
            .ok_or_else(|| Error::Mls("a founding staged no Welcome".into()))?;
        // The copy of the Welcome sent to this device must open nothing. A
        // last-resort package is kept, as it always is, and opens nothing
        // either: its entry seals no group's secrets.
        if !own.last_resort() {
            let reference = own.hash_ref(self.provider.crypto()).map_err(mls_err)?;
            self.provider.storage().delete_key_package(&reference)?;
        }
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;

        // STAGED, NOT MERGED. See §The commit lifecycle.
        Ok(CommitBundle {
            commit,
            welcome: Some(welcome),
            epoch: group.epoch().as_u64() + 1,
        })
    }

    /// Remove the member at a leaf index, holding the leaf key the caller read
    /// beside it ([`RosterEntry::leaf_key`]).
    ///
    /// By leaf index and not by actor id, because a person may have several
    /// devices in one group and removing "Ada" is a product decision about
    /// which leaves that means. [`Self::leaf_of_device`] turns a device id into
    /// the index when that is what the caller has.
    ///
    /// The key is checked against the leaf at that index in the tree the store
    /// holds now, after the reload: an index read from an earlier roster can
    /// name a leaf a later commit emptied and refilled ("remove D, add E" puts
    /// E on D's leaf), and a removal by index alone would then remove E.
    /// A key that no longer matches is [`Error::NoSuchMember`], with nothing
    /// staged: read the roster again.
    pub fn remove_member(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
        expected_leaf_key: &[u8],
    ) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome = client.remove_member_inner(group_id, leaf_index, expected_leaf_key, true);
            client.stage_committed(group_id, outcome)
        })
    }

    /// [`Self::remove_member`] with the policy and lapsed-leaf checks OFF, so
    /// a test can hand every other member a Remove signed by a lapsed leaf, as
    /// a modified client would, and prove they refuse it. See `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_remove_member(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
        expected_leaf_key: &[u8],
    ) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome =
                client.remove_member_inner(group_id, leaf_index, expected_leaf_key, false);
            client.stage_committed(group_id, outcome)
        })
    }

    fn remove_member_inner(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
        expected_leaf_key: &[u8],
        honest: bool,
    ) -> Result<CommitBundle> {
        let ctx = if honest {
            self.own_context(ProposalKind::Remove)
        } else {
            ProposalContext::from_member(ProposalKind::Remove)
        };
        self.rules.evaluate(&ctx).into_result()?;

        if !self
            .groups
            .get(group_id)
            .ok_or(Error::NoSuchGroup)?
            .is_active()
        {
            return Err(Error::NotAMember);
        }
        if honest {
            self.refuse_if_own_leaf_lapsed(group_id)?;
        }
        self.refuse_if_commit_staged(group_id)?;
        // Nothing queued rides along (see `add_member`).
        let index = LeafNodeIndex::new(leaf_index);
        {
            let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
            let member = group
                .members()
                .find(|member| member.index == index)
                .ok_or(Error::NoSuchMember)?;
            // The leaf moved since the caller read it: re-read the roster.
            if member.signature_key.as_slice() != expected_leaf_key {
                return Err(Error::NoSuchMember);
            }
        }
        let plan = CommitPlan {
            removes: vec![leaf_index],
            proposals_len: CommitPlan::inline_proposal(4),
            ..CommitPlan::default()
        };
        let bundle = self.padded_commit(group_id, &plan, |this| {
            let provider = &this.provider;
            let signer = &this.signer;
            let group = this.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            group
                .commit_builder()
                .consume_proposal_store(false)
                .propose_removals([index])
                .load_psks(provider.storage())
                .map_err(mls_err)?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(mls_err)?
                .stage_commit(provider)
                .map_err(mls_err)
        })?;
        if honest {
            self.refuse_own_commit_receivers_would_refuse(group_id)?;
        }
        let commit = bundle.commit().to_bytes().map_err(mls_err)?;
        // A Welcome only ever travels in a frame (crate::welcome_frame).
        let welcome = match bundle.to_welcome_msg() {
            Some(message) => Some(crate::welcome_frame::frame_welcome(
                &message.to_bytes().map_err(mls_err)?,
                0,
            )?),
            None => None,
        };
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        // STAGED, NOT MERGED. See §The commit lifecycle.
        Ok(CommitBundle {
            commit,
            welcome,
            epoch: group.epoch().as_u64() + 1,
        })
    }

    /// LEAVE: a standalone proposal to remove `leaf_index`, one of this
    /// device's own person's leaves (its own included).
    ///
    /// A member cannot commit its own removal (RFC 9420 §12.2), so it
    /// proposes it and another member commits it
    /// ([`Self::commit_proposed_leaves`]). A person leaving proposes the
    /// removal of each of their leaves, sends each proposal to the group as an
    /// ordinary message (envelope kind [`crate::envelope::ENVELOPE_KIND_MESSAGE`]),
    /// and then forgets the group ([`Self::forget_group`]). Every member's
    /// device stores the proposals (the commit names them by reference), and
    /// the first to commit them takes the person out; every member then draws
    /// "{name} left" from [`CommitOutcome::left`].
    ///
    /// The proposals are sealed at this epoch. A different commit that takes
    /// the epoch first drops them, and the leaves then stay until somebody
    /// removes them or they lapse (docs/sealed-messages.md
    /// §Removal). The leaving device does not wait to see which: it has
    /// already forgotten the group, so it reads nothing either way.
    pub fn propose_leave(&mut self, group_id: &[u8], leaf_index: u32) -> Result<Vec<u8>> {
        self.synced(|client| client.propose_leave_now(group_id, leaf_index))
    }

    fn propose_leave_now(&mut self, group_id: &[u8], leaf_index: u32) -> Result<Vec<u8>> {
        if !self
            .groups
            .get(group_id)
            .ok_or(Error::NoSuchGroup)?
            .is_active()
        {
            return Err(Error::NotAMember);
        }
        self.refuse_if_own_leaf_lapsed(group_id)?;
        self.refuse_if_commit_staged(group_id)?;
        match self.seated_identity(group_id, leaf_index) {
            Some(identity) if identity.actor_id == self.identity.actor_id => {}
            Some(_) => {
                return Err(Error::invalid(
                    "a leave proposes the removal of this person's own leaves only",
                ))
            }
            None => return Err(Error::NoSuchMember),
        }
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        let (message, _reference) = group
            .propose_remove_member(&self.provider, &self.signer, LeafNodeIndex::new(leaf_index))
            .map_err(mls_err)?;
        let bytes = message.to_bytes().map_err(mls_err)?;
        // A proposal is a write (the proposal store, the handshake ratchet),
        // committed before the call returns like any other.
        self.flushed_and_erased(bytes)
    }

    /// LEAVE A GROUP UNTIL IT TAKES: propose the removal of every leaf of
    /// this device's own person (its own included) and keep the group as a
    /// LEAVING stub, which nothing but the leave reads. Returns the
    /// proposals, each to be sent to the group's leaves as a message
    /// (envelope kind [`crate::envelope::ENVELOPE_KIND_MESSAGE`], not urgent).
    ///
    /// The proposals are sealed at this epoch, and a different commit that
    /// takes the epoch first drops them. So the device does not forget the
    /// group yet: it follows the group's commits
    /// ([`Self::follow_leave`]) and proposes again at every epoch it reaches
    /// while still seated, until a commit removes it; then it forgets the
    /// group. Meanwhile the stub is in no listing ([`Self::group_ids`]),
    /// opens no message and makes no commit; only [`Self::open_envelope`]
    /// still finds it, so its commits reach the leave.
    ///
    /// Empty, with the group forgotten at once, when nobody but this
    /// device's own person holds a leaf: nobody is left to commit the leave.
    /// Empty too for a group already being left.
    pub fn begin_leave(&mut self, group_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.synced(|client| client.begin_leave_now(group_id))
    }

    fn begin_leave_now(&mut self, group_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        if self.leaving.contains_key(group_id) {
            return Ok(Vec::new());
        }
        let epoch = self.epoch(group_id)?;
        let Some(proposals) = self.leave_proposals_now(group_id)? else {
            self.finish_leave(group_id)?;
            return Ok(Vec::new());
        };
        self.provider
            .peachy_storage()
            .set_leaving(group_id, epoch)?;
        if let Some(group) = self.groups.remove(group_id) {
            self.refused_commits.remove(group_id);
            self.leaving.insert(group_id.to_vec(), group);
        }
        self.flushed_and_erased(proposals)
    }

    /// Whether this device is leaving `group_id` ([`Self::begin_leave`]): a
    /// caller hands each commit envelope of it to [`Self::follow_leave`],
    /// drops every other envelope of it unread, and shows nothing of it.
    pub fn is_leaving(&self, group_id: &[u8]) -> bool {
        self.leaving.contains_key(group_id)
    }

    /// Who a leave's proposals go to: the `(actor id, device id)` of every
    /// leaf of a group this device is LEAVING whose credential identifies,
    /// as [`Self::roster`] reads them, this device's own included (the
    /// caller drops its own as for any send), in device-id order and once
    /// each, as every send lists its recipients: a device id two leaves
    /// claim is named once, under the first actor in order.
    /// [`Error::NoSuchGroup`] for a group this device is not leaving:
    /// [`Self::roster`] answers for those.
    pub fn leave_recipients(&self, group_id: &[u8]) -> Result<Vec<(String, String)>> {
        let group = self.leaving.get(group_id).ok_or(Error::NoSuchGroup)?;
        let mut recipients: Vec<(String, String)> = group
            .members()
            .filter_map(|member| {
                self.identity_provider
                    .validate_seated_credential(
                        &member.credential,
                        &member.signature_key,
                        crate::identity::EXPIRED_LEAF_GRACE_SECONDS,
                    )
                    .ok()
                    .map(|(identity, _)| (identity.actor_id, identity.device_id))
            })
            .collect();
        recipients.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        recipients.dedup_by(|a, b| a.1 == b.1);
        Ok(recipients)
    }

    /// Follow a group this device is LEAVING through one commit entry (a
    /// raw or carried commit, as the commit door takes it), and return the
    /// proposals to send again, if any.
    ///
    /// - The commit removed this device: the leave took. The group is
    ///   forgotten, its kept roster with it, and nothing is returned.
    /// - The commit moved the group on with this device still seated: its
    ///   person's leaves are proposed again at the new epoch (once per
    ///   epoch), for the caller to send as [`Self::begin_leave`]'s were.
    /// - The commit opened and was refused, so this device can no longer
    ///   follow the group ([`Self::commit_strands`]): the leave is given up
    ///   and the group forgotten. The leaves then stay in the others' trees
    ///   until somebody removes them or they lapse; this device does not ask
    ///   back in.
    /// - Anything else (not a commit of this group, an old one): nothing.
    ///
    /// Only a transient store failure is an error: hold the entry and try
    /// again. [`Error::NoSuchGroup`] for a group this device is not leaving.
    pub fn follow_leave(&mut self, group_id: &[u8], message: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.synced(|client| {
            let group = client.leaving.remove(group_id).ok_or(Error::NoSuchGroup)?;
            client.groups.insert(group_id.to_vec(), group);
            let outcome = client.follow_leave_now(group_id, message);
            // Back out of sight, unless the leave is over and it is gone.
            if let Some(group) = client.groups.remove(group_id) {
                client.refused_commits.remove(group_id);
                client.leaving.insert(group_id.to_vec(), group);
            }
            outcome
        })
    }

    fn follow_leave_now(&mut self, group_id: &[u8], message: &[u8]) -> Result<Vec<Vec<u8>>> {
        match self.process_commit(group_id, message) {
            Ok(Incoming::Commit(outcome)) if outcome.removed_self => {
                self.finish_leave(group_id)?;
                Ok(Vec::new())
            }
            Ok(Incoming::Commit(_)) => self.propose_leave_again(group_id),
            Ok(_) => Ok(Vec::new()),
            Err(Error::Storage(err)) => Err(Error::Storage(err)),
            Err(err) => {
                if self.commit_strands(group_id, message)? {
                    log::warn!(
                        "peachy-mls: a group this device is leaving moved on without it — the \
                         leave is given up: {err}"
                    );
                    self.finish_leave(group_id)?;
                } else {
                    log::info!("peachy-mls: a commit entry of a group being left not taken: {err}");
                }
                Ok(Vec::new())
            }
        }
    }

    /// Propose the leave again at the epoch the group is at now, unless it
    /// was already proposed at it. A leave that can no longer be proposed
    /// (nobody else is left, or this device's leaf lapsed, which the others
    /// remove on their own) is given up and the group forgotten.
    fn propose_leave_again(&mut self, group_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        let epoch = self.epoch(group_id)?;
        if self.provider.peachy_storage().leaving(group_id)? == Some(epoch) {
            return Ok(Vec::new());
        }
        match self.leave_proposals_now(group_id) {
            Ok(Some(proposals)) => {
                self.provider
                    .peachy_storage()
                    .set_leaving(group_id, epoch)?;
                self.flushed_and_erased(proposals)
            }
            Ok(None) => {
                self.finish_leave(group_id)?;
                Ok(Vec::new())
            }
            Err(Error::Storage(err)) => Err(Error::Storage(err)),
            Err(err) => {
                log::warn!("peachy-mls: a leave could not be proposed again — given up: {err}");
                self.finish_leave(group_id)?;
                Ok(Vec::new())
            }
        }
    }

    /// A Remove proposal for every leaf of this device's own person in
    /// `group_id` (held in [`Self::groups`]), at its current epoch. `None`
    /// when no leaf is anybody else's: nobody could commit them.
    fn leave_proposals_now(&mut self, group_id: &[u8]) -> Result<Option<Vec<Vec<u8>>>> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if !group.is_active() {
            return Err(Error::NotAMember);
        }
        let mut own = Vec::new();
        let mut others = false;
        for member in group.members() {
            match self.identity_provider.validate_seated_credential(
                &member.credential,
                &member.signature_key,
                i64::MAX,
            ) {
                Ok((identity, _)) if identity.actor_id == self.identity.actor_id => {
                    own.push(member.index);
                }
                // A leaf that does not identify is still somebody's, who
                // may yet commit.
                _ => others = true,
            }
        }
        if !others {
            return Ok(None);
        }
        self.refuse_if_own_leaf_lapsed(group_id)?;
        self.refuse_if_commit_staged(group_id)?;
        let mut proposals = Vec::with_capacity(own.len());
        for leaf in own {
            let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            let (message, _reference) = group
                .propose_remove_member(&self.provider, &self.signer, leaf)
                .map_err(mls_err)?;
            proposals.push(message.to_bytes().map_err(mls_err)?);
        }
        Ok(Some(proposals))
    }

    /// The leave is over, or given up: forget `group_id` (held in
    /// [`Self::groups`]) as a person who left on purpose does, its kept
    /// roster and leaving record with it.
    fn finish_leave(&mut self, group_id: &[u8]) -> Result<()> {
        self.forget_group_now(group_id)?;
        let storage = self.provider.peachy_storage();
        storage.forget_remembered_roster(group_id)?;
        storage.forget_departed(group_id)?;
        storage.forget_rejoin_report(group_id)?;
        // WHO EACH KEY WAS goes too, though the commit that took this device
        // out just wrote it again: a seal for a group left on purpose names
        // nobody, so it draws nothing into the conversation that was left.
        storage.forget_leaf_people(group_id)?;
        // And the group's past holds, as [`Self::forget_remembered_roster`]
        // drops them: a store read later keeps no sign the group was ever
        // stalled on this device, and a seat in it again is held afresh.
        storage.forget_hold_history(group_id)?;
        // And the leaves its conversation settled for the security-code
        // notice: kept only across a rejoin, and this is no rejoin.
        storage.forget_account_leaf_records(group_id)?;
        self.flushed(())
    }

    /// Commit the LEAVES this device holds ([`Self::propose_leave`]): one
    /// commit naming by reference every queued Remove of a leaf of its
    /// proposer's own person, and nothing else. `None` when there is none to
    /// commit, including when every one queued is this device's own person's
    /// (a member cannot commit its own removal; this device forgets the group
    /// on its person's leave record instead).
    ///
    /// Staged, not merged, like every other commit (§The commit lifecycle):
    /// submit it, then merge or clear. Several members may stage one for the
    /// same leave; the delivery service takes one commit per epoch, and the
    /// others clear theirs and apply the winner, which already took the
    /// person out. Anything else a proposal store holds is left out.
    ///
    /// **The commit carries the proposals it names**: `commit` is a carried
    /// commit, the proposal messages this device took in ahead of the
    /// commit, so that a member the leave never reached can still apply it.
    /// The stage itself is the bare commit, and so is its echo.
    pub fn commit_proposed_leaves(&mut self, group_id: &[u8]) -> Result<Option<CommitBundle>> {
        self.synced(
            |client| match client.commit_proposed_leaves_inner(group_id) {
                Ok(None) => client.flushed(None),
                Ok(Some((bundle, carried))) => {
                    let mut bundle = client.stage_committed(group_id, Ok(bundle))?;
                    if !carried.is_empty() {
                        bundle.commit =
                            crate::carried_commit::carry_proposals(&carried, &bundle.commit)?;
                    }
                    Ok(Some(bundle))
                }
                Err(err) => client.stage_committed(group_id, Err(err)).map(Some),
            },
        )
    }

    /// The commit of the leaves queued here, staged, and the proposal
    /// messages it is to carry.
    #[allow(clippy::type_complexity)]
    fn commit_proposed_leaves_inner(
        &mut self,
        group_id: &[u8],
    ) -> Result<Option<(CommitBundle, Vec<Vec<u8>>)>> {
        if !self
            .groups
            .get(group_id)
            .ok_or(Error::NoSuchGroup)?
            .is_active()
        {
            return Err(Error::NotAMember);
        }
        // The leaves to commit: one queued Remove per leaf, each a leave (by
        // reference, of its proposer's own person's leaf), none this device's
        // own person's.
        let picked: Vec<(ProposalRef, u32)> = {
            let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
            let own_actor = self.identity.actor_id.as_str();
            let actor_at = |index: LeafNodeIndex| {
                group
                    .members()
                    .find(|member| member.index == index)
                    .and_then(|member| {
                        self.identity_provider
                            .validate_seated_credential(
                                &member.credential,
                                &member.signature_key,
                                i64::MAX,
                            )
                            .ok()
                    })
                    .map(|(identity, _)| identity.actor_id)
            };
            let mut picked: Vec<(ProposalRef, u32)> = Vec::new();
            for queued in group.pending_proposals() {
                let openmls::prelude::Proposal::Remove(remove) = queued.proposal() else {
                    continue;
                };
                let removed = remove.removed();
                if !Self::removes_own_leaf(&self.identity_provider, group, queued)
                    || actor_at(removed).as_deref() == Some(own_actor)
                    || picked.iter().any(|(_, leaf)| *leaf == removed.u32())
                {
                    continue;
                }
                picked.push((queued.proposal_reference_ref().clone(), removed.u32()));
            }
            // At most as many as one carried commit brings; any others wait
            // for the next commit.
            picked.truncate(crate::carried_commit::MAX_CARRIED_PROPOSALS);
            picked
        };
        if picked.is_empty() {
            return Ok(None);
        }
        // THE PROPOSALS TO CARRY: each as the message it arrived as. One kept
        // by a build from before the bytes were kept has none, and goes
        // uncarried, as every leave went before.
        let carried: Vec<Vec<u8>> = {
            let epoch = self.epoch(group_id)?;
            let storage = self.provider.peachy_storage();
            let mut carried = Vec::with_capacity(picked.len());
            for (reference, _) in &picked {
                if let Some(message) =
                    storage.carried_leave(group_id, epoch, reference.as_slice())?
                {
                    carried.push(message);
                }
            }
            carried
        };
        self.refuse_if_own_leaf_lapsed(group_id)?;
        self.refuse_if_commit_staged(group_id)?;
        let plan = CommitPlan {
            removes: picked.iter().map(|(_, leaf)| *leaf).collect(),
            proposals_len: picked.len() * CommitPlan::proposal_by_reference(),
            ..CommitPlan::default()
        };
        let refs: Vec<ProposalRef> = picked.into_iter().map(|(reference, _)| reference).collect();
        let bundle = self.padded_commit(group_id, &plan, |this| {
            let provider = &this.provider;
            let signer = &this.signer;
            let group = this.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            group
                .commit_builder()
                .consume_proposal_store(true)
                .load_psks(provider.storage())
                .map_err(mls_err)?
                .build(provider.rand(), provider.crypto(), signer, |queued| {
                    refs.contains(queued.proposal_reference_ref())
                })
                .map_err(mls_err)?
                .stage_commit(provider)
                .map_err(mls_err)
        })?;
        self.refuse_own_commit_receivers_would_refuse(group_id)?;
        let commit = bundle.commit().to_bytes().map_err(mls_err)?;
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        // STAGED, NOT MERGED. See §The commit lifecycle.
        Ok(Some((
            CommitBundle {
                commit,
                welcome: None,
                epoch: group.epoch().as_u64() + 1,
            },
            carried,
        )))
    }

    /// Replace the leaf at `leaf_index` with a fresh one, in ONE commit.
    ///
    /// THE REJOIN, seen from a device that is still awake. Its counterpart on
    /// the sleeping device is [`Self::forget_group`] — see that method for why
    /// there is no way for the stale device to do this itself.
    ///
    /// Remove and Add in a single commit, and it must be a single commit: two
    /// commits would put the group through an epoch in which the person is not
    /// in it, so every other member's roster flickers, any message sent in that
    /// window is one the returning device can never read, and a second
    /// concurrent committer can wedge itself between the two halves and leave
    /// the group with a removal that was never followed by the add. One commit
    /// carries one Welcome, sealed to the new key package, and the returning
    /// device joins at the epoch the commit produced.
    ///
    /// Both halves are policy-checked before anything is built, in the order a
    /// remote member would check them — a replace is not a special proposal
    /// kind on the wire, it is a Remove and an Add in one commit, and it must
    /// pass exactly the rules those two would pass separately.
    ///
    /// The new leaf normally lands back at `leaf_index`, because RFC 9420 fills
    /// the leftmost blank leaf and the Remove just blanked that one — but that
    /// is the tree's business, not a promise. Callers read the new index off
    /// the roster.
    pub fn replace_member(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
        new_key_package: &[u8],
    ) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome = client.stage_replace_member(group_id, leaf_index, new_key_package);
            client.stage_committed(group_id, outcome)
        })
    }

    fn stage_replace_member(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
        new_key_package: &[u8],
    ) -> Result<CommitBundle> {
        let message = MlsMessageIn::tls_deserialize_exact(new_key_package)?;
        let MlsMessageBodyIn::KeyPackage(incoming) = message.extract() else {
            return Err(Error::invalid("that message is not a KeyPackage"));
        };
        let key_package = Self::adder_checked(&self.provider, &self.identity_provider, incoming)?;
        let joining = self.identity_provider.validate_key_package(&key_package)?;
        self.refuse_if_forgotten_own_device(&joining)?;

        self.rules
            .evaluate(&self.own_context(ProposalKind::Remove))
            .into_result()?;
        self.rules
            .evaluate(&self.own_context(ProposalKind::Add))
            .into_result()?;

        let index = LeafNodeIndex::new(leaf_index);
        {
            let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
            if !group.is_active() {
                return Err(Error::NotAMember);
            }
            if !group.members().any(|member| member.index == index) {
                return Err(Error::NoSuchMember);
            }
            if index == group.own_leaf_index() {
                // A device cannot replace its own leaf: the commit would remove
                // the committer, and a commit nobody can be the author of is
                // not a commit. The awake device asks somebody else, or the
                // returning device is added as a new member.
                return Err(Error::invalid(
                    "a member cannot replace its own leaf — ask another member",
                ));
            }
        }
        self.refuse_if_own_leaf_lapsed(group_id)?;
        // Rejected before the commit is built rather than after: a replace that
        // swapped one device's leaf for a different person's would be a silent
        // membership change wearing the shape of a recovery.
        //
        // The leaf is identified IGNORING its expiry. A replace is most often
        // the repair for a device that was away, and a device away long enough
        // has a lapsed leaf credential; reading only leaves that still verify
        // left exactly those unguarded, so the replace would hand an expired
        // seat to anybody. Who a leaf belongs to does not stop being true on
        // its `exp` (docs/identity.md §Refreshing a seated leaf).
        //
        // AND A LEAF WHOSE OWNER CANNOT BE READ AT ALL IS NOT REPLACED. An
        // unreadable seat — its issuer's kid rotated out of the trusted set, a
        // malformed credential — must not skip this guard, or the one leaf
        // nobody can vouch for is the one a replace would hand to anybody.
        // Such a leaf is REMOVED instead (every client's
        // reconcile evicts an unidentified leaf), and its device comes back by
        // an ordinary Add.
        let Some(removed) = self.seated_identity(group_id, leaf_index) else {
            return Err(Error::invalid(
                "a replace needs to know whose leaf it takes; this one cannot be identified",
            ));
        };
        if removed.actor_id != joining.actor_id {
            return Err(Error::invalid(
                "a replace must hand the leaf to the same actor it took it from",
            ));
        }
        // And to the same DEVICE, under the same account identity key. A
        // replace is one device coming back to its own seat; the joining
        // package has already been checked to carry its account's certificate
        // (`validate_key_package`), and this keeps a replace from being the
        // way a different device of that person — or a device under an
        // account key nobody here pinned — takes somebody's seat unannounced.
        if removed.device_id != joining.device_id || removed.account_key != joining.account_key {
            return Err(Error::invalid(
                "a replace must hand the leaf back to the same device, under the same account key",
            ));
        }
        // And under the same DEVICE key. A device coming back to its own seat
        // keeps its signing key: its group state and its key live in one
        // store, and a seat ask is signed by the key the asker holds. A
        // package naming the device's id under another key is another device
        // wearing its name (a server holding a retained account key can mint
        // one), and handing it the seat would evict the real device with no
        // new device for anybody to see. A device that truly lost its key
        // comes back by an ordinary Add, once its old leaf is gone, and is
        // judged as a new device. Receivers refuse a commit made this way
        // too.
        if removed.device_key != joining.device_key {
            return Err(Error::invalid(
                "a replace must hand the leaf back to the same device key",
            ));
        }
        self.refuse_if_device_seated(group_id, &joining, Some(leaf_index))?;

        // The proposal store is NOT consumed. A replace is a repair, and
        // sweeping up whatever proposals happened to be queued would make the
        // repair carry changes nobody asked it to carry.
        let plan = CommitPlan {
            removes: vec![index.u32()],
            adds: 1,
            proposals_len: CommitPlan::inline_proposal(4)
                + CommitPlan::inline_proposal(key_package.tls_serialized_len()),
            ..CommitPlan::default()
        };
        let trees = self.welcome_trees_for(group_id, &plan, [&key_package])?;
        // The epochs this device's seat was held through, while its copy
        // could not follow: what was sealed to it then opens once it is back
        // (crate::welcome_frame §The gap block). Read before the commit is
        // built, at the epoch it leaves.
        let gap = self.reseat_gap(group_id, &removed.device_key)?;
        let bundle = self.padded_commit(group_id, &plan, |this| {
            let provider = &this.provider;
            let signer = &this.signer;
            let group = this.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            group
                .commit_builder()
                .consume_proposal_store(false)
                .propose_removals([index])
                .propose_adds([key_package])
                .load_psks(provider.storage())
                .map_err(mls_err)?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(mls_err)?
                .stage_commit(provider)
                .map_err(mls_err)
        })?;
        self.refuse_own_commit_receivers_would_refuse(group_id)?;
        let commit = bundle.commit().to_bytes().map_err(mls_err)?;
        let welcome = self.welcome_out(&trees, &bundle, None, Some((group_id, &gap[..])))?;
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        // STAGED, NOT MERGED. See §The commit lifecycle.
        Ok(CommitBundle {
            commit,
            welcome,
            epoch: group.epoch().as_u64() + 1,
        })
    }

    /// RESEAT A PERSON WHOSE EVERY DEVICE IS GONE: remove the leaves at
    /// `leaf_indexes`, which must be every leaf of one person in the tree,
    /// and add `key_package`, a new device of that same person, in ONE commit
    /// (docs/identity.md §Revocation reaches a seated leaf through
    /// the roster).
    ///
    /// The one way a person's LAST leaf leaves a group without the account's
    /// signed revocation or a credential past its grace
    /// (`crate::revocation`). A person who lost every device
    /// (`ClaimSoleDevice`) starts over under a new account key, so nothing can
    /// sign their old devices' revocations, and one-person-one-key
    /// ([`crate::policy::judge_account_keys`]) keeps the new device out while
    /// an old leaf stays. Removing the old leaves alone would be the server
    /// removing a member; seating the new device in the same commit keeps the
    /// person a member, and the new device must carry the signature of a new
    /// account key, which every member then shows as the person's security
    /// code changing ([`Self::observe_account_keys`]). The server alone
    /// cannot do it quietly.
    ///
    /// Refused unless the package passes every check an add makes and carries
    /// an account certificate under a key that is FRESH: no removed leaf
    /// carries it, and this device never saw the person move away from it
    /// (`account_retired`), so every reseat changes the person's security
    /// code for every member, and none brings back a key the person left. A
    /// device under the key every named leaf carries is not reseated but
    /// ADDED, beside them, even under a key retired in another group: whoever
    /// holds that key signs the old leaves' revocations, and they go on
    /// that. And it is not this device's own
    /// person (this
    /// device's siblings are seated by its own sweep); every index names an
    /// identified leaf of the package's person and together they are all of
    /// that person's leaves; and none of them is the joining device itself
    /// (that is a [`Self::replace_member`]). The group's policy judges it as
    /// it judges any removal of somebody else.
    ///
    /// **Staged, not merged**, like every other commit here.
    pub fn reseat_person(
        &mut self,
        group_id: &[u8],
        leaf_indexes: &[u32],
        key_package: &[u8],
    ) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome = client.stage_reseat_person(group_id, leaf_indexes, key_package);
            client.stage_committed(group_id, outcome)
        })
    }

    fn stage_reseat_person(
        &mut self,
        group_id: &[u8],
        leaf_indexes: &[u32],
        key_package: &[u8],
    ) -> Result<CommitBundle> {
        let raw_key_package = key_package;
        let (key_package, joining) = self.validated_key_package(key_package)?;
        self.refuse_if_forgotten_own_device(&joining)?;
        let Some(joining_account) = joining.account_key else {
            return Err(Error::invalid(
                "a person is reseated only by a device that carries an account's signature",
            ));
        };
        if joining.actor_id == self.identity.actor_id {
            return Err(Error::invalid(
                "this device's own person is reseated by its own devices, never by a reseat",
            ));
        }
        // Under the same account key there is nothing to reseat: whoever
        // holds that key signs the old leaves' revocations, and one person,
        // one key lets the new device in beside them. It is an ordinary add,
        // and the old leaves go on their own evidence.
        let named_keys: Vec<Option<[u8; 32]>> = leaf_indexes
            .iter()
            .filter_map(|index| self.seated_identity(group_id, *index))
            .filter(|id| id.actor_id == joining.actor_id)
            .map(|id| id.account_key)
            .collect();
        if !named_keys.is_empty() && named_keys.iter().all(|key| *key == Some(joining_account)) {
            return self.stage_add_member(group_id, raw_key_package);
        }
        // Past that add: a key this device saw the person leave, in any group,
        // is not reseated back over the key they moved to.
        if self
            .provider
            .peachy_storage()
            .account_retired(&joining.actor_id)?
            .contains(&joining_account)
        {
            return Err(Error::invalid(
                "a person is never reseated under an account key they moved away from",
            ));
        }
        self.rules
            .evaluate(&self.own_context(ProposalKind::Remove))
            .into_result()?;
        self.rules
            .evaluate(&self.own_context(ProposalKind::Add))
            .into_result()?;
        let mut removals: Vec<u32> = leaf_indexes.to_vec();
        removals.sort_unstable();
        removals.dedup();
        if removals.is_empty() || removals.len() != leaf_indexes.len() {
            return Err(Error::invalid(
                "a reseat names each of the person's leaves once, and at least one",
            ));
        }
        {
            let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
            if !group.is_active() {
                return Err(Error::NotAMember);
            }
            let own = group.own_leaf_index().u32();
            for member in group.members() {
                let index = member.index.u32();
                let named = removals.contains(&index);
                if named && index == own {
                    return Err(Error::invalid(
                        "a reseat cannot remove the committer's own leaf",
                    ));
                }
                let identity = self.seated_identity(group_id, index);
                match (named, identity) {
                    (true, Some(id)) if id.actor_id == joining.actor_id => {
                        if id.device_id == joining.device_id || id.device_key == joining.device_key
                        {
                            return Err(Error::invalid(
                                "that device already holds a leaf here; a device comes back by a replace of its own leaf",
                            ));
                        }
                        // A person seated under two keys at once: a seat
                        // under one of them changes no security code.
                        if id.account_key == Some(joining_account) {
                            return Err(Error::invalid(
                                "a reseat seats a new account key, never one a removed leaf carries",
                            ));
                        }
                    }
                    (true, _) => {
                        return Err(Error::invalid(
                            "a reseat removes only identified leaves of the person it seats",
                        ));
                    }
                    (false, Some(id)) if id.actor_id == joining.actor_id => {
                        return Err(Error::invalid(
                            "a reseat removes every leaf of the person it seats",
                        ));
                    }
                    (false, _) => {}
                }
            }
            if removals
                .iter()
                .any(|index| !group.members().any(|m| m.index.u32() == *index))
            {
                return Err(Error::NoSuchMember);
            }
        }
        self.refuse_if_device_seated(group_id, &joining, None)?;
        self.refuse_if_own_leaf_lapsed(group_id)?;
        self.refuse_if_commit_staged(group_id)?;

        let indexes: Vec<LeafNodeIndex> =
            removals.iter().copied().map(LeafNodeIndex::new).collect();
        let plan = CommitPlan {
            removes: removals.clone(),
            adds: 1,
            proposals_len: removals.len() * CommitPlan::inline_proposal(4)
                + CommitPlan::inline_proposal(key_package.tls_serialized_len()),
            ..CommitPlan::default()
        };
        let trees = self.welcome_trees_for(group_id, &plan, [&key_package])?;
        let bundle = self.padded_commit(group_id, &plan, |this| {
            let provider = &this.provider;
            let signer = &this.signer;
            let group = this.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            group
                .commit_builder()
                .consume_proposal_store(false)
                .propose_removals(indexes.iter().copied())
                .propose_adds([key_package])
                .load_psks(provider.storage())
                .map_err(mls_err)?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(mls_err)?
                .stage_commit(provider)
                .map_err(mls_err)
        })?;
        self.refuse_own_commit_receivers_would_refuse(group_id)?;
        let commit = bundle.commit().to_bytes().map_err(mls_err)?;
        let welcome = self
            .welcome_out(&trees, &bundle, None, None)?
            .ok_or_else(|| Error::Mls("a reseat staged no Welcome".into()))?;
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        // STAGED, NOT MERGED. See §The commit lifecycle.
        Ok(CommitBundle {
            commit,
            welcome: Some(welcome),
            epoch: group.epoch().as_u64() + 1,
        })
    }

    /// The trees every member's add would put in this commit's Welcome
    /// ([`welcome_trees`]), read before the commit is built: what its frame
    /// is padded by.
    fn welcome_trees_for<'k>(
        &self,
        group_id: &[u8],
        plan: &CommitPlan,
        joiners: impl IntoIterator<Item = &'k KeyPackage>,
    ) -> Result<WelcomeTrees> {
        let joiner_leaves = joiners
            .into_iter()
            .map(|key_package| key_package.leaf_node().tls_serialized_len())
            .sum();
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        welcome_trees(group, plan, joiner_leaves)
    }

    /// The Welcome a built commit sends, if it adds anybody: framed and
    /// padded to a bound set by `trees` ([`Self::welcome_trees_for`]), the
    /// tree's width, its members and their leaves, so its length on the
    /// network says neither who made it nor who committed before; the
    /// server reads the length inside (crate::welcome_frame). A founding's Welcome
    /// carries a seat for this device's own `founder_seat` package too
    /// (crate::founding). A reseat's carries `gap`, the group and the epochs
    /// its joiner's seat was held through, sealed to the new epoch in a
    /// version 2 frame (crate::welcome_frame §The gap block).
    fn welcome_out(
        &mut self,
        trees: &WelcomeTrees,
        bundle: &openmls::prelude::CommitMessageBundle,
        founder_seat: Option<&KeyPackage>,
        gap: Option<(&[u8], &[EpochSecret])>,
    ) -> Result<Option<Vec<u8>>> {
        let Some(message) = bundle.to_welcome_msg() else {
            return Ok(None);
        };
        let mut raw = message.to_bytes().map_err(mls_err)?;
        if let Some(own) = founder_seat {
            raw = crate::founding::with_founder_seat(&raw, own, self.provider.crypto())?;
        }
        let group_info = bundle
            .group_info()
            .ok_or_else(|| Error::Mls("a commit with a Welcome exported no GroupInfo".into()))?;
        let bound = welcome_bound_len(trees, group_info, &raw)?;
        let target = welcome_padding_target(bound, &raw, gap.is_some());
        #[cfg(feature = "test-forgery")]
        {
            self.welcome_bound_seen = Some(bound);
        }
        let Some((group_id, gap)) = gap else {
            return crate::welcome_frame::frame_welcome(&raw, target).map(Some);
        };
        #[cfg(feature = "test-forgery")]
        let gap: &[(u64, [u8; 32])] = if self.hands_back_no_gap { &[] } else { gap };
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        let staged = group
            .pending_commit()
            .ok_or_else(|| Error::Mls("a reseat's Welcome needs its staged commit".into()))?;
        let key = Zeroizing::new(
            staged
                .export_secret(
                    self.provider.crypto(),
                    crate::welcome_frame::WELCOME_GAP_EXPORTER_LABEL,
                    group_id,
                    32,
                )
                .map_err(mls_err)?,
        );
        let block = crate::welcome_frame::seal_gap_block(&key, gap)?;
        crate::welcome_frame::frame_welcome_with_gap(&raw, &block, target).map(Some)
    }

    /// The epochs whose envelopes were sealed to the device of
    /// `device_key` while it held its seat in `group_id`, newest first, with
    /// their envelope secrets: the epoch the group is at, then each kept
    /// epoch below it until the one whose commit (re)added that device, an
    /// epoch this copy did not keep, or an epoch whose commit's adds it did
    /// not record. At most [`crate::welcome_frame::WELCOME_GAP_EPOCHS`].
    ///
    /// Never an epoch before the device was (re)added: a device removed and
    /// added back gets nothing sealed while it was out.
    fn reseat_gap(
        &self,
        group_id: &[u8],
        device_key: &[u8; 32],
    ) -> Result<crate::welcome_frame::GapSecrets> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        let current = group.epoch().as_u64();
        // Sized for the most a gap holds before the first push, so no
        // reallocation leaves a copy of a secret behind; wiped when dropped.
        let mut gap = crate::welcome_frame::GapSecrets::new(Vec::with_capacity(
            crate::welcome_frame::WELCOME_GAP_EPOCHS,
        ));
        gap.push((current, *self.envelope_epoch_secret(group_id, group)?));
        let records = self
            .provider
            .peachy_storage()
            .envelope_epoch_records(group_id)?;
        let digest = device_key_digest(device_key);
        let mut epoch = current;
        while gap.len() < crate::welcome_frame::WELCOME_GAP_EPOCHS {
            let Some(below) = epoch.checked_sub(1) else {
                break;
            };
            let Some(record) = records.iter().find(|record| record.epoch == below) else {
                break;
            };
            match &record.added_next {
                Some(added) if !added.contains(&digest) => {}
                _ => break,
            }
            gap.push((below, *record.secret));
            epoch = below;
        }
        Ok(gap)
    }

    /// Keep the epochs a reseat's gap block hands back to this device
    /// (crate::welcome_frame §The gap block), sealed to the epoch it was
    /// seated at, `seated_epoch`. Only epochs below that one are kept. A
    /// block that does not open costs the seat nothing: it is logged and
    /// dropped, and what was sealed in those epochs stays unopened.
    fn keep_welcome_gap(&mut self, group_id: &[u8], seated_epoch: u64, block: &[u8]) -> Result<()> {
        let Some(group) = self.groups.get(group_id) else {
            return Ok(());
        };
        let key = Zeroizing::new(
            group
                .export_secret(
                    self.provider.crypto(),
                    crate::welcome_frame::WELCOME_GAP_EXPORTER_LABEL,
                    group_id,
                    32,
                )
                .map_err(mls_err)?,
        );
        let mut gap = match crate::welcome_frame::open_gap_block(&key, block) {
            Ok(gap) => gap,
            Err(err) => {
                log::warn!("peachy-mls: a reseat's gap block did not open: {err}");
                return Ok(());
            }
        };
        // In place: the dropped entries stay in the vector's own spare
        // capacity, which is wiped with it.
        gap.retain(|(epoch, _)| *epoch < seated_epoch);
        self.provider
            .peachy_storage()
            .set_envelope_gap(group_id, &gap)?;
        self.reopen_anew();
        Ok(())
    }

    /// Keep a version 3 envelope that opens for no group this device holds,
    /// so that it opens once this device holds the epoch it was sealed at:
    /// a copy that fell behind or forked meets these until a member returns
    /// its seat, and the Welcome that does hands back the epochs it missed
    /// (crate::welcome_frame §The gap block). [`Self::next_reopenable`]
    /// gives each back when it opens; the caller then takes it through the
    /// same path as a fresh one, which draws a placeholder and asks for the
    /// message again when the MLS message inside does not open.
    ///
    /// `mailbox_kind`, `id` and `received_at_ms` are the mailbox's own, kept
    /// for that path. Answers whether it was kept: not when it is no version
    /// 3 envelope, when it opens now, when one with its id or its very bytes
    /// is held, or when those bytes were held on a seal and released. At
    /// most [`HELD_ENVELOPES_KEPT`], oldest dropped first, and none older
    /// than [`HELD_ENVELOPE_MAX_AGE_MS`].
    pub fn hold_envelope(
        &mut self,
        mailbox_kind: u8,
        id: &str,
        received_at_ms: u64,
        envelope: &[u8],
    ) -> Result<bool> {
        Ok(
            self.hold_envelope_sealed(mailbox_kind, id, received_at_ms, envelope, &[])?
                == HoldAnswer::Kept,
        )
    }

    /// [`Self::hold_envelope`], with the DEVICE SEAL the mailbox handed over
    /// beside the envelope (`MailboxEnvelope.device_seal`; empty for none).
    ///
    /// A seal that opens for this device ([`crate::device_seal`]) names the
    /// group, the sender and the epoch secret the envelope was sealed under,
    /// whatever this device's copy holds. Then only a message is kept (one
    /// of any other kind answers false: it is stale by the time it could
    /// open), apart from the envelopes held without one, ONCE PER ENVELOPE:
    /// keyed by the SHA-256 of its bytes, so the same envelope handed over
    /// under any number of mailbox ids is held, and handed out, once. A copy
    /// of it held without a seal steps aside for it. [`Self::next_reopenable`]
    /// hands it out on what the seal carried ([`HeldFate`]).
    ///
    /// The envelopes held on seals are bounded by bytes, not by count: past
    /// [`SEALED_HELD_BUDGET_BYTES`] (the newest kept first) or 30 days old,
    /// one is due to be handed out ([`Self::next_reopenable`] says how), and
    /// past three quarters of the ceiling it is handed out at the next pass
    /// whatever its copy's epoch. One that would take the hold past
    /// [`SEALED_HELD_MAX`] envelopes or [`SEALED_HELD_MAX_BYTES`] is held
    /// without its seal instead, as the newest of the hold without seals,
    /// and answered [`HoldAnswer::Full`]: the caller stops its page there,
    /// unacknowledged, and drains again once the pass has made room; the same
    /// envelope delivered again then takes its place on its seal. Nothing at
    /// the ceiling is lost that the hold without seals would have kept.
    ///
    /// A seal that does not open is ignored, and the envelope is held as
    /// without one. One for a message this device opened before (a replay of
    /// one taken through and let go) is not held.
    pub fn hold_envelope_sealed(
        &mut self,
        mailbox_kind: u8,
        id: &str,
        received_at_ms: u64,
        envelope: &[u8],
        seal: &[u8],
    ) -> Result<HoldAnswer> {
        if !crate::envelope::envelope_is_epoch_keyed(envelope) || id.is_empty() {
            return Ok(HoldAnswer::NotKept);
        }
        self.synced(|client| {
            let outcome =
                client.hold_envelope_now(mailbox_kind, id, received_at_ms, envelope, seal);
            client.flushed(())?;
            outcome
        })
    }

    fn hold_envelope_now(
        &mut self,
        mailbox_kind: u8,
        id: &str,
        received_at_ms: u64,
        envelope: &[u8],
        seal: &[u8],
    ) -> Result<HoldAnswer> {
        // Opens now, a held seal's grant included: nothing to keep.
        if let Some(mut opened) = self.open_envelope(envelope)? {
            zeroize::Zeroize::zeroize(&mut opened.inner);
            return Ok(HoldAnswer::NotKept);
        }
        let digest: [u8; 32] = sha2::Sha256::digest(envelope).into();
        let storage = self.provider.peachy_storage();
        // ONE ENVELOPE, HELD ONCE, whatever mailbox id it comes under; and
        // never again once released.
        if storage.sealed_hold(&digest)?.is_some() || storage.held_released(&digest)? {
            return Ok(HoldAnswer::NotKept);
        }
        let mut holds = storage.sealed_holds()?;
        if holds.iter().any(|hold| hold.id == id) {
            return Ok(HoldAnswer::NotKept);
        }
        let mut held = storage.held_envelopes()?;
        // Held without a seal already, under this id or with these bytes: a
        // seal that reads now may still take its place below.
        let unsealed = held
            .iter()
            .any(|entry| entry.id == id || entry.envelope == envelope);
        let now = u64::try_from(self.identity_provider.now_unix_ms()).unwrap_or(0);
        let told = match self.read_device_seal(seal, envelope) {
            SealRead::Message(told) => Some(told),
            SealRead::NotAMessage | SealRead::Opened => return Ok(HoldAnswer::NotKept),
            SealRead::Unread => None,
        };
        let limits = self.sealed_limits;
        let bytes: u64 = holds.iter().map(|hold| u64::from(hold.bytes)).sum();
        let length = u32::try_from(envelope.len()).ok();
        let room = length.is_some_and(|length| {
            holds.len() < limits.max && bytes.saturating_add(u64::from(length)) <= limits.max_bytes
        });
        let sealed = told.is_some();
        let Some((told, length)) = told.zip(length).filter(|_| room) else {
            // NO SEAL, OR NO ROOM FOR ONE: held as without a seal.
            if unsealed {
                // Held without its seal by another process (the
                // notification extension, which answered FULL and stopped):
                // FULL here too, once, so this drain makes room and the seal
                // is not lost to an acknowledgement.
                if sealed && !self.hold_full_told {
                    self.hold_full_told = true;
                    // The pass that makes room runs again, though this
                    // process's last one ended with nothing to hand out.
                    self.reopen_anew();
                    return Ok(HoldAnswer::Full);
                }
                return Ok(HoldAnswer::NotKept);
            }
            let before = held.len();
            if now.saturating_sub(received_at_ms) > HELD_ENVELOPE_MAX_AGE_MS {
                Self::settle_held(&mut held, now);
                if held.len() != before {
                    storage.set_held_envelopes(&held)?;
                }
                return Ok(HoldAnswer::NotKept);
            }
            held.push(crate::storage::HeldEnvelope {
                mailbox_kind,
                received_at_ms,
                id: id.to_string(),
                envelope: envelope.to_vec(),
            });
            held.sort_by_key(|entry| entry.received_at_ms);
            Self::settle_held(&mut held, now);
            storage.set_held_envelopes(&held)?;
            self.reopen_anew();
            if !sealed || self.hold_full_told {
                return Ok(HoldAnswer::Kept);
            }
            log::warn!(
                "peachy-mls: the hold on device seals is at its ceiling ({} envelopes, {bytes} bytes): one held without its seal, and the page stops",
                holds.len()
            );
            self.hold_full_told = true;
            return Ok(HoldAnswer::Full);
        };
        // The same bytes, or the same id, held without their seal step aside.
        if unsealed {
            held.retain(|entry| entry.id != id && entry.envelope != envelope);
            storage.set_held_envelopes(&held)?;
        }
        let hold = crate::storage::SealedHold {
            digest,
            mailbox_kind,
            received_at_ms,
            bytes: length,
            epoch: told.epoch,
            due: crate::storage::HoldDue::Waiting,
            handed: false,
            secret: crate::storage::held_secret(&told.secret),
            sender_key: told.sender_key,
            group_id: told.group_id,
            id: id.to_owned(),
        };
        storage.set_sealed_hold(&hold, Some(envelope))?;
        holds.push(hold);
        holds.sort_by_key(|h| (h.received_at_ms, h.digest));
        self.settle_sealed(&mut holds, now)?;
        self.reopen_anew();
        Ok(HoldAnswer::Kept)
    }

    /// What a device seal beside `envelope` tells this device
    /// ([`Self::hold_envelope_sealed`]).
    fn read_device_seal(&self, seal: &[u8], envelope: &[u8]) -> SealRead {
        if seal.is_empty() {
            return SealRead::Unread;
        }
        let Ok(opened) = crate::device_seal::device_seal_open_keyed(
            &self.device_seal_secret,
            self.signer.public(),
            seal,
            envelope,
        ) else {
            log::info!("peachy-mls: a device seal did not open");
            return SealRead::Unread;
        };
        let Ok((kind, inner)) =
            crate::envelope::open_epoch_envelope(&opened.epoch_secret[..], envelope)
        else {
            log::info!("peachy-mls: a device seal's secret did not open its envelope");
            return SealRead::Unread;
        };
        if kind != crate::envelope::ENVELOPE_KIND_MESSAGE {
            return SealRead::NotAMessage;
        }
        let Some(peek) = crate::hint::peek_message(&inner) else {
            return SealRead::Unread;
        };
        // A REPLAY of a message this device took through already (its
        // release note lapsed): nothing to hold.
        let seen = self
            .provider
            .peachy_storage()
            .opened_before(&opened.group_id, &crate::storage::opened_digest(&inner));
        if seen.unwrap_or(false) {
            log::info!("peachy-mls: a sealed envelope not held: its message was opened before");
            return SealRead::Opened;
        }
        SealRead::Message(SealTold {
            epoch: peek.epoch,
            secret: Zeroizing::new(*opened.epoch_secret),
            sender_key: opened.sender_key,
            group_id: opened.group_id,
        })
    }

    /// Hold the envelopes kept without a seal to the age and the count the
    /// hold keeps: past either, the oldest go.
    fn settle_held(held: &mut Vec<crate::storage::HeldEnvelope>, now: u64) {
        let excess = held.len().saturating_sub(HELD_ENVELOPES_KEPT);
        let mut at = 0;
        held.retain(|entry| {
            at += 1;
            at > excess && now.saturating_sub(entry.received_at_ms) <= HELD_ENVELOPE_MAX_AGE_MS
        });
    }

    /// Raise how pressed each envelope held on its seal is to be handed out
    /// (`holds` oldest first), counting from the newest: past the byte
    /// budget or 30 days, due; past three quarters of the ceiling, urgent.
    /// A raised record is written back. Nothing here drops one.
    fn settle_sealed(&self, holds: &mut [crate::storage::SealedHold], now: u64) -> Result<()> {
        use crate::storage::HoldDue;
        let limits = self.sealed_limits;
        let urgent_count = limits.max - limits.max / 4;
        let urgent_bytes = limits.max_bytes - limits.max_bytes / 4;
        let storage = self.provider.peachy_storage();
        let (mut count, mut bytes) = (0usize, 0u64);
        for hold in holds.iter_mut().rev() {
            count += 1;
            bytes = bytes.saturating_add(u64::from(hold.bytes));
            let due = if count > urgent_count || bytes > urgent_bytes {
                HoldDue::Urgent
            } else if bytes > limits.budget_bytes
                || now.saturating_sub(hold.received_at_ms) > HELD_ENVELOPE_MAX_AGE_MS
            {
                HoldDue::Due
            } else {
                HoldDue::Waiting
            };
            if due > hold.due {
                hold.due = due;
                storage.set_sealed_hold(hold, None)?;
            }
        }
        Ok(())
    }

    /// Whether the words of the message inside held envelope `hold` were
    /// kept when it was taken through before ([`Self::process_message_as`]),
    /// under its mailbox id and that message's own digest: a record under
    /// the id for another message does not count.
    fn sealed_words_kept(&self, hold: &crate::storage::SealedHold) -> Result<bool> {
        if hold.id.is_empty() || hold.id.contains('\0') {
            return Ok(false);
        }
        let storage = self.provider.peachy_storage();
        let Some(envelope) = storage.sealed_hold_envelope(&hold.digest)? else {
            return Ok(false);
        };
        let Ok((_, inner)) = crate::envelope::open_epoch_envelope(&hold.secret[..], &envelope)
        else {
            return Ok(false);
        };
        let digest = crate::storage::opened_digest(&inner);
        Ok(storage.opened_content(&hold.id, &digest)?.is_some())
    }

    /// Whether, and how, envelope `hold` is handed out on its seal now.
    ///
    /// - Its secret is one this device holds for the group: it opens as any
    ///   envelope does, with no grant ([`SealVerdict::Plain`]).
    /// - Handed out before and its words are kept ([`Self::process_message_as`]
    ///   kept them in the write that spent the key): granted as it was.
    /// - Its group's copy is held: it waits while the copy is not past the
    ///   message's epoch, and, while it is merely behind and the envelope is
    ///   under 30 days old and not urgent, past the budget too. Then: from a
    ///   leaf of the copy, granted; from a key THIS GROUP's record
    ///   ([`crate::storage::LeafPeople`]) holds whose person holds a leaf
    ///   still, granted (that device was replaced); whose person holds none,
    ///   a placeholder naming them ([`HeldFate::FormerMember`]). Dropped
    ///   when it was sealed at or after the epoch the key left at, or this
    ///   device saw the key go more than 30 days ago, whether or not its
    ///   person holds a leaf still. A key only another group's record holds
    ///   is granted only when its person holds a leaf of this one, and never
    ///   named on a placeholder.
    /// - No copy held: it waits until due, then, from a key the group's own
    ///   record holds (kept 30 days after the copy was let go), it is an
    ///   orphan ([`HeldFate::Orphan`]) naming its sender, or a former
    ///   member's placeholder when they had left by then.
    /// - Any other key is no word of anybody's: anybody can make a seal from
    ///   a key of their own, and a key seen in one group is no word about
    ///   another. Kept as without a seal ([`SealVerdict::Unsealed`]): an
    ///   honest member who joined while this copy was away opens there once
    ///   a reseat hands the epoch back.
    fn sealed_verdict(
        &self,
        hold: &crate::storage::SealedHold,
        own_secrets: &[Zeroizing<[u8; 32]>],
        people: &mut SealPeople,
        now: u64,
    ) -> Result<SealVerdict> {
        use crate::storage::HoldDue;
        if own_secrets.iter().any(|own| own[..] == hold.secret[..]) {
            return Ok(SealVerdict::Plain);
        }
        let storage = self.provider.peachy_storage();
        if hold.handed && self.sealed_words_kept(hold)? {
            return Ok(SealVerdict::Grant(HeldFate::Ordinary, None, false));
        }
        let group = self
            .groups
            .get(&hold.group_id)
            .or_else(|| self.leaving.get(&hold.group_id))
            .filter(|group| group.is_active());
        if let Some(group) = group {
            let copy = group.epoch().as_u64();
            let young = now.saturating_sub(hold.received_at_ms) <= HELD_ENVELOPE_MAX_AGE_MS;
            let waits = hold.due == HoldDue::Waiting && copy <= hold.epoch;
            let behind = hold.due < HoldDue::Urgent && copy < hold.epoch && young;
            if waits || behind {
                return Ok(SealVerdict::Wait);
            }
            if group
                .members()
                .any(|member| member.signature_key.as_slice() == hold.sender_key.as_slice())
            {
                return Ok(SealVerdict::Grant(HeldFate::Ordinary, None, false));
            }
        } else if hold.due == HoldDue::Waiting {
            return Ok(SealVerdict::Wait);
        }
        if !people.groups.contains_key(&hold.group_id) {
            let mut record = storage.leaf_people(&hold.group_id)?;
            // A TIME A KEY LEFT noted ahead of the clock is kept as now, so a
            // clock set back does not stretch its 30 days on the next pass.
            if let Some(record) = record.as_mut() {
                if record.clamp_left_at(now) {
                    storage.set_leaf_people(&hold.group_id, record)?;
                }
            }
            people.groups.insert(hold.group_id.clone(), record);
        }
        let record = people.groups.get(&hold.group_id).and_then(Option::as_ref);
        let Some(person) = record.and_then(|r| r.person_of(&hold.sender_key)) else {
            // NOT A KEY OF THIS GROUP: another group's record may name its
            // person, and only a person seated here is granted on it, as any
            // member's envelope; nobody is named on a placeholder by it.
            if group.is_some() {
                if people.anywhere.is_none() {
                    people.anywhere = Some(storage.leaf_people_index()?);
                }
                let actor = people
                    .anywhere
                    .as_ref()
                    .and_then(|index| index.get(&hold.sender_key));
                if let Some(actor) = actor.filter(|actor| record.is_some_and(|r| r.seated(actor))) {
                    return Ok(SealVerdict::Grant(
                        HeldFate::Ordinary,
                        Some(actor.clone()),
                        true,
                    ));
                }
            }
            log::info!(
                "peachy-mls: a sealed envelope kept without its seal: its group never held its sender"
            );
            return Ok(SealVerdict::Unsealed);
        };
        let actor = person.actor_id.clone();
        if person.left_epoch != 0 && hold.epoch >= person.left_epoch {
            log::info!("peachy-mls: a sealed envelope dropped: sealed after its sender left");
            return Ok(SealVerdict::Drop);
        }
        // A KEY GONE FROM THE TREE (its person left, or replaced the device):
        // taken on for 30 days after this device saw it go, by its own clock,
        // as long as the mailbox keeps what it sent before; never after. A
        // time noted ahead of the clock counts as now.
        if person.left_at_ms != 0
            && now.saturating_sub(person.left_at_ms.min(now)) > HELD_ENVELOPE_MAX_AGE_MS
        {
            log::info!(
                "peachy-mls: a sealed envelope dropped: its sender's device left more than 30 days ago"
            );
            return Ok(SealVerdict::Drop);
        }
        let seated = record.is_some_and(|r| r.seated(&actor));
        if group.is_some() && seated {
            return Ok(SealVerdict::Grant(HeldFate::Ordinary, Some(actor), true));
        }
        if !seated {
            // A FORMER MEMBER, within the 30 days above.
            return Ok(SealVerdict::Grant(
                HeldFate::FormerMember,
                Some(actor),
                false,
            ));
        }
        Ok(SealVerdict::Grant(HeldFate::Orphan, Some(actor), false))
    }

    /// The next envelope [`Self::hold_envelope`] kept that opens now, oldest
    /// first; `None` when none does. A caller asks after every mailbox pass,
    /// and again after each one it is given, until `None`. The envelope STAYS
    /// kept until the caller releases it ([`Self::release_held`]) once what
    /// it made of it (a placeholder, a resend ask) is stored: within a pass
    /// it is not handed out twice, and one not released is handed out again
    /// in the next pass, or after a restart. Cheap when nothing changed: no
    /// held envelope is read until an epoch was entered, a gap handed back or
    /// an envelope left unreleased since the last `None`; and a pass reads
    /// the held records once, at its first call, then hands them out in turn.
    ///
    /// One handed out on its DEVICE SEAL ([`crate::device_seal`]) is granted
    /// until it is released: [`Self::open_envelope`] opens those very bytes
    /// on the secret the seal carried, however many others are handed out
    /// first, and [`Self::held_disposition`] says what it is to be made of.
    /// Its record goes only with the release, so one handed out again after
    /// a restart is granted again, after the membership check runs again.
    pub fn next_reopenable(&mut self) -> Result<Option<crate::storage::HeldEnvelope>> {
        if !self.reopen_due {
            return Ok(None);
        }
        self.synced(|client| {
            let outcome = client.next_reopenable_now();
            client.flushed(())?;
            outcome
        })
    }

    fn next_reopenable_now(&mut self) -> Result<Option<crate::storage::HeldEnvelope>> {
        if self.reopen_queue.is_none() {
            let queue = self.held_reopen_pass()?;
            self.reopen_queue = Some(queue);
        }
        loop {
            let Some(next) = self
                .reopen_queue
                .as_mut()
                .and_then(std::collections::VecDeque::pop_front)
            else {
                // THE PASS IS OVER. One handed out and not released was not
                // taken through (the caller stopped early, or failed on it):
                // it is handed out again in the next pass.
                self.reopen_queue = None;
                if self.reopen_handed.is_empty() {
                    self.reopen_due = false;
                } else {
                    self.reopen_handed.clear();
                }
                return Ok(None);
            };
            let id = match &next {
                Reopenable::Plain(entry) => &entry.id,
                Reopenable::Sealed(hold, _) => &hold.id,
            };
            if self.reopen_handed.contains_key(id) {
                continue;
            }
            let (entry, digest) = match next {
                Reopenable::Plain(entry) => (entry, None),
                Reopenable::Sealed(mut hold, verdict) => {
                    let storage = self.provider.peachy_storage();
                    let Some(envelope) = storage.sealed_hold_envelope(&hold.digest)? else {
                        storage.delete_sealed_hold(&hold.digest)?;
                        continue;
                    };
                    if let SealVerdict::Grant(fate, author, by_person) = verdict {
                        let Ok((_, inner)) =
                            crate::envelope::open_epoch_envelope(&hold.secret[..], &envelope)
                        else {
                            storage.delete_sealed_hold(&hold.digest)?;
                            continue;
                        };
                        if !hold.handed {
                            hold.handed = true;
                            storage.set_sealed_hold(&hold, None)?;
                        }
                        self.seal_grants.insert(
                            hold.digest,
                            SealGrant {
                                id: hold.id.clone(),
                                group_id: hold.group_id.clone(),
                                secret: hold.secret.clone(),
                                sender_key: hold.sender_key,
                                inner_digest: sha2::Sha256::digest(&inner).into(),
                                fate,
                                author,
                                by_person,
                            },
                        );
                    }
                    (
                        crate::storage::HeldEnvelope {
                            mailbox_kind: hold.mailbox_kind,
                            received_at_ms: hold.received_at_ms,
                            id: hold.id,
                            envelope,
                        },
                        Some(hold.digest),
                    )
                }
            };
            self.reopen_handed.insert(entry.id.clone(), digest);
            return Ok(Some(entry));
        }
    }

    /// One pass's worth of held envelopes that open now, oldest first, read
    /// once: the hold settled to its age, count and budget, each sealed one
    /// judged ([`Self::sealed_verdict`]), and those dropped deleted. The
    /// first pass of a client's life, and the first after each
    /// [`OPENED_PRUNE_EVERY_MS`], also sweeps what a cut-short write or the
    /// 30 days left behind.
    fn held_reopen_pass(&mut self) -> Result<std::collections::VecDeque<Reopenable>> {
        let now = u64::try_from(self.identity_provider.now_unix_ms()).unwrap_or(0);
        let oldest = now.saturating_sub(HELD_ENVELOPE_MAX_AGE_MS);
        let storage = self.provider.peachy_storage();
        if self
            .held_swept_at_ms
            .is_none_or(|at| now.saturating_sub(at) >= OPENED_PRUNE_EVERY_MS)
        {
            storage.sweep_sealed_holds()?;
            storage.prune_held_released(oldest, crate::storage::HELD_RELEASED_KEPT)?;
            storage.prune_leaf_people(oldest, now)?;
            self.held_swept_at_ms = Some(now);
        }
        let mut held = storage.held_envelopes()?;
        let before = held.len();
        Self::settle_held(&mut held, now);
        if held.len() != before {
            storage.set_held_envelopes(&held)?;
        }
        let mut holds = storage.sealed_holds()?;
        self.settle_sealed(&mut holds, now)?;
        let mut secrets: Vec<Zeroizing<[u8; 32]>> = Vec::new();
        if !held.is_empty() || !holds.is_empty() {
            // Every group's secrets read first, so `secrets` is sized once
            // and copied into: a Vec that grows copies its secrets into a new
            // block and frees the old one unwiped. What was read wipes
            // itself as it drops.
            let mut read = Vec::with_capacity(self.groups.len() + self.leaving.len());
            for (group_id, group) in self.groups.iter().chain(self.leaving.iter()) {
                let current = if group.is_active() {
                    self.envelope_epoch_secret(group_id, group).ok()
                } else {
                    None
                };
                read.push((
                    current,
                    storage.envelope_epochs(group_id)?,
                    storage.envelope_gap(group_id)?,
                ));
            }
            secrets.reserve_exact(
                read.iter()
                    .map(|(current, epochs, gap)| {
                        usize::from(current.is_some()) + epochs.len() + gap.len()
                    })
                    .sum(),
            );
            for (current, epochs, gap) in &read {
                secrets.extend(current.iter().map(|secret| Zeroizing::new(**secret)));
                secrets.extend(epochs.iter().map(|(_, _, secret)| Zeroizing::new(**secret)));
                secrets.extend(gap.iter().map(|(_, secret)| Zeroizing::new(*secret)));
            }
        }
        let mut pass: Vec<(u64, Reopenable)> = held
            .into_iter()
            .filter(|entry| {
                secrets.iter().any(|secret| {
                    crate::envelope::epoch_envelope_is_for(&secret[..], &entry.envelope)
                })
            })
            .map(|entry| (entry.received_at_ms, Reopenable::Plain(entry)))
            .collect();
        let mut people = SealPeople::default();
        for hold in holds {
            match self.sealed_verdict(&hold, &secrets, &mut people, now)? {
                SealVerdict::Wait => {}
                SealVerdict::Drop => {
                    // Not noted released: the same bytes delivered again
                    // under another seal (their author's own) are held again.
                    self.provider
                        .peachy_storage()
                        .delete_sealed_hold(&hold.digest)?;
                    self.seal_grants.remove(&hold.digest);
                    self.hold_full_told = false;
                }
                SealVerdict::Unsealed => {
                    // A KEY THE GROUP'S RECORD NEVER HELD names nobody, but
                    // may be an honest member who joined while this copy was
                    // forked or away: the envelope is kept as one that came
                    // with no seal, which opens only on a secret this device
                    // gets from its group (a reseat's gap block).
                    self.demote_sealed(&hold, now)?;
                    self.seal_grants.remove(&hold.digest);
                    self.hold_full_told = false;
                }
                verdict => pass.push((hold.received_at_ms, Reopenable::Sealed(hold, verdict))),
            }
        }
        pass.sort_by_key(|(at, _)| *at);
        Ok(pass.into_iter().map(|(_, entry)| entry).collect())
    }

    /// Keep envelope `hold`, held on a seal that names nobody, as an envelope
    /// that came with no seal: it leaves the hold on seals, and is kept with
    /// the envelopes held without one, by their rules (one already there
    /// under its id or with its bytes is not kept twice; one past the age is
    /// not kept).
    fn demote_sealed(&mut self, hold: &crate::storage::SealedHold, now: u64) -> Result<()> {
        let storage = self.provider.peachy_storage();
        let envelope = storage.sealed_hold_envelope(&hold.digest)?;
        storage.delete_sealed_hold(&hold.digest)?;
        let Some(envelope) = envelope else {
            return Ok(());
        };
        let mut held = storage.held_envelopes()?;
        if held
            .iter()
            .any(|entry| entry.id == hold.id || entry.envelope == envelope)
        {
            return Ok(());
        }
        held.push(crate::storage::HeldEnvelope {
            mailbox_kind: hold.mailbox_kind,
            received_at_ms: hold.received_at_ms,
            id: hold.id.clone(),
            envelope,
        });
        held.sort_by_key(|entry| entry.received_at_ms);
        Self::settle_held(&mut held, now);
        storage.set_held_envelopes(&held)?;
        Ok(())
    }

    /// What envelope `id`, handed out by [`Self::next_reopenable`] on its
    /// device seal and not yet released, is to be made of; `None` for one
    /// handed out on no seal's grant, which is taken through as any other.
    pub fn held_disposition(&self, id: &str) -> Option<HeldDisposition> {
        self.seal_grants
            .values()
            .find(|grant| grant.id == id)
            .map(|grant| HeldDisposition {
                fate: grant.fate,
                author: grant.author.clone(),
            })
    }

    /// Release an envelope [`Self::next_reopenable`] handed out: what the
    /// caller made of it is stored, and it is kept no longer. Answers whether
    /// one with that id was kept.
    ///
    /// The id leaves this pass's handed-out set only once the release is
    /// stored. A release whose write fails leaves it kept AND handed out, so
    /// the same pass does not hand it out again (a caller looping on
    /// [`Self::next_reopenable`] would take it through again, and again); the
    /// next pass does.
    pub fn release_held(&mut self, id: &str) -> Result<bool> {
        let digest = self.reopen_handed.get(id).copied().flatten();
        let released = self.synced(|client| {
            let outcome = client.release_held_now(id, digest);
            client.flushed(())?;
            outcome
        })?;
        self.reopen_handed.remove(id);
        // ITS SEAL'S GRANT IS SPENT: the same bytes delivered again are not
        // held again ([`Self::hold_envelope_sealed`]).
        if let Some(digest) = released {
            self.seal_grants.remove(&digest);
        }
        Ok(released.is_some())
    }

    /// An envelope held on its seal goes with its record, and its digest is
    /// noted released, in one write: a seal is never let go before what its
    /// envelope made is stored. Answers the digest released (all zeros for
    /// one held without a seal), or `None` for nothing held under `id`.
    fn release_held_now(&mut self, id: &str, digest: Option<[u8; 32]>) -> Result<Option<[u8; 32]>> {
        let storage = self.provider.peachy_storage();
        let hold = match digest {
            Some(digest) => storage.sealed_hold(&digest)?.filter(|hold| hold.id == id),
            None => storage
                .sealed_holds()?
                .into_iter()
                .find(|hold| hold.id == id),
        };
        if let Some(hold) = hold {
            let now = u64::try_from(self.identity_provider.now_unix_ms()).unwrap_or(0);
            storage.delete_sealed_hold(&hold.digest)?;
            // ONE REFUSED as not by the device its seal named is not noted:
            // the same bytes under their author's own seal are held again.
            // Nor is one granted on its seal that this process did not grant
            // ([`Self::next_reopenable`]; a release after a restart): whether
            // it was refused is kept in memory only, so it is not known here.
            let refused = self.seal_refused.remove(&hold.digest);
            let known = !hold.handed || self.seal_grants.contains_key(&hold.digest);
            if known && !refused {
                storage.note_held_released(&hold.digest, now)?;
            }
            self.hold_full_told = false;
            return Ok(Some(hold.digest));
        }
        let mut held = storage.held_envelopes()?;
        let before = held.len();
        held.retain(|entry| entry.id != id);
        if held.len() == before {
            return Ok(None);
        }
        storage.set_held_envelopes(&held)?;
        Ok(Some([0; 32]))
    }

    /// The reopen pass starts again: an epoch was entered, a gap handed back,
    /// a copy let go or an envelope held, so what opens may have changed.
    fn reopen_anew(&mut self) {
        self.reopen_due = true;
        self.reopen_queue = None;
    }

    /// Hold envelopes on seals to these limits instead of
    /// [`SEALED_HELD_BUDGET_BYTES`], [`SEALED_HELD_MAX`] and
    /// [`SEALED_HELD_MAX_BYTES`]: what a test holds the budget and the
    /// ceiling to without sending megabytes. See `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn limit_sealed_hold(&mut self, budget_bytes: u64, max: usize, max_bytes: u64) {
        self.sealed_limits = SealedLimits {
            budget_bytes,
            max: max.max(1),
            max_bytes,
        };
    }

    /// Hand back no gap in this client's reseats, as a member of a build
    /// without the gap block would: what a test holds the gap block's
    /// absence to. See `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn act_as_member_handing_back_no_gap(&mut self) {
        self.hands_back_no_gap = true;
    }

    /// Stand in for a build without [`Self::refuse_to_seal_on_lapsed_leaf`]:
    /// application messages are sealed whatever the tree clock says of this
    /// device's leaf, so a test can hand receivers what an older or modified
    /// client would send. See `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn act_as_build_sending_while_lapsed(&mut self) {
        self.sends_while_lapsed = true;
    }

    /// Stand in for a build with [`crate::steward::STEWARD_READS`] on: an
    /// enrolled group is held, and a veto skips or rejoins. See
    /// `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn act_as_build_honoring_stewards(&mut self) {
        self.honors_stewards = true;
    }

    /// The raw Welcome length the last framed add or reseat was padded to
    /// (before the frame's header and block): the bound no member's Welcome
    /// exceeds. See `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn welcome_bound_seen(&self) -> Option<usize> {
        self.welcome_bound_seen
    }

    // ---- Policy inputs -------------------------------------------------------

    /// This client as the proposer: an ordinary member's context.
    fn own_context(&self, kind: ProposalKind) -> ProposalContext {
        ProposalContext::from_member(kind)
    }

    /// The policy input for one incoming proposal.
    ///
    /// The one place a `QueuedProposal` is turned into a
    /// [`ProposalContext`], so the outgoing side and the incoming side cannot
    /// read the same commit differently. `current` is the group context as it
    /// stands BEFORE the commit, which is what
    /// [`crate::group_meta::group_meta_change`] diffs against.
    fn proposal_context(
        identity_provider: &PeachyIdentityProvider,
        group: &MlsGroup,
        queued: &openmls::prelude::QueuedProposal,
    ) -> ProposalContext {
        let current = group.extensions();
        let proposal = queued.proposal();
        ProposalContext {
            kind: ProposalKind::from(proposal),
            sender: SenderKind::from(queued.sender()),
            targets_sender_leaf: Self::update_targets_sender(queued),
            sets_group_meta: match proposal {
                openmls::prelude::Proposal::GroupContextExtensions(gce) => {
                    group_meta_change(current, gce.extensions())
                }
                _ => false,
            },
            // A standalone proposal, and one a commit names by its reference
            // rather than carries, is somebody's change that a different
            // member commits; the rules refuse it (`crate::rules` §Why
            // proposals by reference are refused).
            by_reference: queued.proposal_or_ref_type()
                == openmls::prelude::ProposalOrRefType::Reference,
            // By reference, a leave: the one proposal the rules take that way.
            removes_own_leaf: Self::removes_own_leaf(identity_provider, group, queued),
        }
    }

    /// Whether `queued` is a Remove of a leaf of its sender's own person.
    ///
    /// Both leaves are read off `group` (the tree BEFORE the commit that
    /// would carry it) with every credential check but the clock: whose a
    /// leaf is does not stop being true on its `exp`, and a verdict with no
    /// clock in it cannot differ between two members. A leaf no check reads
    /// is nobody's, so its removal is never a leave.
    fn removes_own_leaf(
        identity_provider: &PeachyIdentityProvider,
        group: &MlsGroup,
        queued: &openmls::prelude::QueuedProposal,
    ) -> bool {
        let (openmls::prelude::Proposal::Remove(remove), openmls::prelude::Sender::Member(sender)) =
            (queued.proposal(), queued.sender())
        else {
            return false;
        };
        let actor_at = |index: LeafNodeIndex| {
            group
                .members()
                .find(|member| member.index == index)
                .and_then(|member| {
                    identity_provider
                        .validate_seated_credential(
                            &member.credential,
                            &member.signature_key,
                            i64::MAX,
                        )
                        .ok()
                })
                .map(|(identity, _)| identity.actor_id)
        };
        match (actor_at(*sender), actor_at(remove.removed())) {
            (Some(proposer), Some(removed)) => proposer == removed,
            _ => false,
        }
    }

    // ---- What the group says about itself -----------------------------------

    /// Open a member-rostered conversation's envelope
    /// ([`crate::envelope`]) against every group this device holds, the
    /// groups it is leaving included ([`Self::is_leaving`]: a caller hands
    /// those commits to [`Self::follow_leave`] and drops the rest). `None`
    /// when it is for no group here — a conversation this device has left,
    /// or bytes that are not an envelope at all.
    ///
    /// A version 3 envelope is tried against the epoch each held copy is at
    /// now, then against the epochs each has kept
    /// ([`ENVELOPE_PAST_EPOCHS`] of them), then against the epochs a reseat
    /// handed back ([`crate::welcome_frame`] §The gap block). One that opens
    /// for none was sealed at an epoch this device never held or has let
    /// go: before its seat, or ahead of it, which is what a copy that fell
    /// behind or forked meets ([`crate::envelope::envelope_is_epoch_keyed`]
    /// tells a caller so, and [`Self::hold_envelope`] keeps it until its
    /// epoch is handed back).
    pub fn open_envelope(
        &self,
        envelope: &[u8],
    ) -> Result<Option<crate::envelope::OpenedEnvelope>> {
        if !crate::envelope::envelope_is_epoch_keyed(envelope) {
            return crate::envelope::open_envelope_among(
                self.groups
                    .keys()
                    .chain(self.leaving.keys())
                    .map(Vec::as_slice),
                envelope,
            );
        }
        let held = || self.groups.iter().chain(self.leaving.iter());
        for (group_id, group) in held() {
            if !group.is_active() {
                continue;
            }
            let Ok(secret) = self.envelope_epoch_secret(group_id, group) else {
                continue;
            };
            if let Ok((kind, mut inner)) =
                crate::envelope::open_epoch_envelope(&secret[..], envelope)
            {
                return Ok(Some(crate::envelope::OpenedEnvelope {
                    group_id: group_id.clone(),
                    kind,
                    inner: std::mem::take(&mut *inner),
                }));
            }
        }
        let storage = self.provider.peachy_storage();
        for (group_id, _) in held() {
            for (_, _, secret) in storage.envelope_epochs(group_id)?.iter().rev() {
                if let Ok((kind, mut inner)) =
                    crate::envelope::open_epoch_envelope(&secret[..], envelope)
                {
                    return Ok(Some(crate::envelope::OpenedEnvelope {
                        group_id: group_id.clone(),
                        kind,
                        inner: std::mem::take(&mut *inner),
                    }));
                }
            }
        }
        // Then the epochs a reseat handed back: sealed to this device while
        // its copy could not follow (crate::welcome_frame §The gap block).
        for (group_id, _) in held() {
            for (_, secret) in storage.envelope_gap(group_id)?.iter() {
                if let Ok((kind, mut inner)) =
                    crate::envelope::open_epoch_envelope(secret, envelope)
                {
                    return Ok(Some(crate::envelope::OpenedEnvelope {
                        group_id: group_id.clone(),
                        kind,
                        inner: std::mem::take(&mut *inner),
                    }));
                }
            }
        }
        // Last, an envelope `Self::next_reopenable` handed out on its device
        // seal and not yet released: opened on the secret the seal carried,
        // for those very bytes alone.
        if !self.seal_grants.is_empty() {
            let digest: [u8; 32] = sha2::Sha256::digest(envelope).into();
            if let Some(grant) = self.seal_grants.get(&digest) {
                if let Ok((kind, mut inner)) =
                    crate::envelope::open_epoch_envelope(grant.secret.as_slice(), envelope)
                {
                    return Ok(Some(crate::envelope::OpenedEnvelope {
                        group_id: grant.group_id.clone(),
                        kind,
                        inner: std::mem::take(&mut *inner),
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Wrap `inner` as an envelope of `group_id` ([`crate::envelope`]): the
    /// door every send, commit, typing frame and call signal of a held group
    /// goes through.
    ///
    /// Sealed by the EPOCH (version 3, keys from
    /// `MLS-Exporter("peachy envelope epoch v1", group id, 32)`), so a
    /// removed member, who keeps the group id but not the next epoch,
    /// recognizes and opens nothing sealed after its removal.
    ///
    /// The epoch is the one the inner MLS message was made in, read off its
    /// header: a commit wrapped after it merged is sealed under the epoch it
    /// was built in, the one its receivers are still at. A typing frame or a
    /// call signal takes the epoch the copy is at. A message or commit made
    /// at an epoch this copy no longer keeps is refused with
    /// [`Error::StaleCopy`] (encrypt it again), anything but a seat ask or a
    /// link preview from a copy no longer in the group with
    /// [`Error::NotAMember`], and from a group this device does not hold with
    /// [`Error::NoSuchGroup`]; none falls back to the group id.
    ///
    /// By the group id (version 2) only: a seat ask and a link preview,
    /// whose openers hold no epoch of the group.
    pub fn seal_envelope(&self, group_id: &[u8], kind: u8, inner: &[u8]) -> Result<Vec<u8>> {
        match self.epoch_envelope_secret_for(group_id, kind, inner)? {
            Some(secret) => crate::envelope::seal_epoch_envelope(&secret[..], kind, inner),
            None => crate::envelope::seal_group_id_envelope(group_id, kind, inner),
        }
    }

    /// A DEVICE SEAL ([`crate::device_seal`]) for `envelope`, a version 3
    /// envelope of any kind this device sealed to `group_id` under one of its
    /// epochs, for EVERY leaf of its copy, this device's own included: each
    /// leaf's device key with the seal made for it, to ride beside the
    /// envelope to that device's mailbox (`SealedRecipient.device_seal`). A
    /// send addresses every device, the sender's own too, so every entry
    /// carries a seal, whatever the envelope holds, and none of them marks
    /// the sending device or the kind. A leaf whose key no seal can be made
    /// for gets 226 random bytes behind the version byte in its seal's place,
    /// which open for nobody, so its entry looks like every other. Empty when
    /// `envelope` is not sealed under an epoch this copy holds, or the group
    /// id is too long to seal.
    ///
    /// No build sends a seal ([`crate::device_seal::DEVICE_SEAL_SENDS`] is
    /// false) and every build reads one; this is the sending half, held to
    /// the reading half by the tests.
    pub fn device_seals(
        &self,
        group_id: &[u8],
        envelope: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if group_id.len() > crate::device_seal::DEVICE_SEAL_MAX_GROUP_ID_BYTES {
            return Ok(Vec::new());
        }
        let Some(group) = self
            .groups
            .get(group_id)
            .or_else(|| self.leaving.get(group_id))
            .filter(|group| group.is_active())
        else {
            return Ok(Vec::new());
        };
        // Read in place, never moved: a list of these secrets that grew, or
        // that was iterated by value, would leave their bytes in the blocks
        // it frees. Each wipes itself where it lies as it drops.
        let current = self.envelope_epoch_secret(group_id, group)?;
        let kept = self.provider.peachy_storage().envelope_epochs(group_id)?;
        let Some(secret) = std::iter::once(&current)
            .chain(kept.iter().map(|(_, _, secret)| secret))
            .find(|secret| crate::envelope::open_epoch_envelope(&secret[..], envelope).is_ok())
        else {
            return Ok(Vec::new());
        };
        let own = self.signer.public();
        let mut seals = Vec::new();
        for member in group.members() {
            let key = member.signature_key;
            let seal = if crate::device_seal::device_key_is_sealable(&key) {
                crate::device_seal::device_seal_keyed(
                    &self.device_seal_secret,
                    own,
                    &key,
                    group_id,
                    &secret[..],
                    envelope,
                )?
            } else {
                crate::device_seal::device_seal_filler()?
            };
            seals.push((key, seal));
        }
        Ok(seals)
    }

    /// The epoch envelope secret [`Self::seal_envelope`] seals `inner` under,
    /// `None` for the group id's keys (a seat ask or a link preview), or the
    /// refusal of an envelope no held epoch can seal.
    fn epoch_envelope_secret_for(
        &self,
        group_id: &[u8],
        kind: u8,
        inner: &[u8],
    ) -> Result<Option<Zeroizing<[u8; 32]>>> {
        use crate::envelope::{
            ENVELOPE_KIND_COMMIT, ENVELOPE_KIND_LINK_PREVIEW, ENVELOPE_KIND_MESSAGE,
            ENVELOPE_KIND_SEAT_ASK,
        };
        if kind == ENVELOPE_KIND_SEAT_ASK || kind == ENVELOPE_KIND_LINK_PREVIEW {
            return Ok(None);
        }
        let Some(group) = self
            .groups
            .get(group_id)
            .or_else(|| self.leaving.get(group_id))
        else {
            return Err(Error::NoSuchGroup);
        };
        if !group.is_active() {
            return Err(Error::NotAMember);
        }
        let current = group.epoch().as_u64();
        let made_at = if kind == ENVELOPE_KIND_MESSAGE || kind == ENVELOPE_KIND_COMMIT {
            crate::hint::peek_message(inner).map(|peek| peek.epoch)
        } else {
            None
        }
        .unwrap_or(current);
        if made_at == current {
            return self.envelope_epoch_secret(group_id, group).map(Some);
        }
        // An earlier epoch: a commit built there and merged since. Sealed
        // under it only if this copy kept it.
        // Copied out of the record, not moved: a list iterated by value
        // frees the block it leaves the secrets' bytes in.
        // One it no longer keeps is refused, never sealed by the group id:
        // its receivers no longer keep that epoch either.
        let kept = self.provider.peachy_storage().envelope_epochs(group_id)?;
        kept.iter()
            .find(|(epoch, _, _)| *epoch == made_at)
            .map(|(_, _, secret)| Some(Zeroizing::new(**secret)))
            .ok_or(Error::StaleCopy {
                message_epoch: made_at,
                copy_epoch: current,
            })
    }

    /// `group`'s envelope secret at the epoch it is at now:
    /// `MLS-Exporter("peachy envelope epoch v1", group id, 32)`.
    fn envelope_epoch_secret(
        &self,
        group_id: &[u8],
        group: &MlsGroup,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let secret = Zeroizing::new(
            group
                .export_secret(
                    self.provider.crypto(),
                    crate::envelope::EPOCH_ENVELOPE_EXPORTER_LABEL,
                    group_id,
                    32,
                )
                .map_err(mls_err)?,
        );
        <[u8; 32]>::try_from(secret.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| Error::Mls("an exported envelope secret is 32 bytes".into()))
    }

    /// Keep the envelope secret of the epoch the copy of `group_id` is at
    /// now ([`crate::storage`] `envelope_epochs`), so an envelope sealed at
    /// it still opens, and a commit built at it is still sealed under it,
    /// once the copy has moved on. Called before every merge, with the
    /// leaves the merging commit adds (digests of their device keys, what
    /// [`Self::reseat_gap`] walks by), and at every epoch the copy enters,
    /// with `None`.
    fn note_envelope_epoch(
        &self,
        group_id: &[u8],
        added_next: Option<Vec<[u8; 32]>>,
    ) -> Result<()> {
        let Some(group) = self
            .groups
            .get(group_id)
            .or_else(|| self.leaving.get(group_id))
        else {
            return Ok(());
        };
        if !group.is_active() {
            return Ok(());
        }
        let secret = self.envelope_epoch_secret(group_id, group)?;
        self.provider.peachy_storage().note_envelope_epoch(
            group_id,
            group.epoch().as_u64(),
            true,
            &secret,
            ENVELOPE_PAST_EPOCHS + 1,
            added_next,
        )?;
        Ok(())
    }

    /// The capabilities this device's leaves and key packages advertise.
    fn leaf_capabilities(&self) -> Capabilities {
        peachy_leaf_capabilities()
    }

    /// [`Self::leaf_capabilities`] for a last-resort package.
    fn last_resort_leaf_capabilities(&self) -> Capabilities {
        peachy_last_resort_leaf_capabilities()
    }

    /// The group's own name-and-photo value, read off its context, or `None`
    /// when nobody has set one (docs/sealed-messages.md §The name is in the group).
    ///
    /// The bytes are the client format (`mls/fixtures/formats/group-meta.json`)
    /// and are returned unparsed: every client's codec refuses what it cannot
    /// read, and that refusal is the reader's, not this crate's.
    pub fn group_meta(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        Ok(group_meta_from_context(group.extensions()))
    }

    /// Set the group's name and photo: one commit carrying a
    /// `GroupContextExtensions` proposal that changes `peachy_group_meta` and
    /// nothing else.
    ///
    /// Any member may. Every receiver
    /// runs the same check on the way in (`sets_group_meta` in
    /// [`crate::rules`]), so a proposal that changes anything besides the meta
    /// is refused by everybody, not just by the client that would have built
    /// it.
    ///
    /// **Staged, not merged**, like every other commit here.
    pub fn set_group_meta(&mut self, group_id: &[u8], value: &[u8]) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome = client.stage_group_meta(group_id, value);
            client.stage_committed(group_id, outcome)
        })
    }

    fn stage_group_meta(&mut self, group_id: &[u8], value: &[u8]) -> Result<CommitBundle> {
        self.rules
            .evaluate(&ProposalContext {
                sets_group_meta: true,
                ..self.own_context(ProposalKind::GroupContextExtensions)
            })
            .into_result()?;
        let extensions = {
            let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
            if !group.is_active() {
                return Err(Error::NotAMember);
            }
            group_context_extensions_with_meta(group.extensions(), value)?
        };
        self.refuse_if_own_leaf_lapsed(group_id)?;

        let plan = CommitPlan {
            proposals_len: CommitPlan::inline_proposal(extensions.tls_serialized_len()),
            ..CommitPlan::default()
        };
        let bundle = self.padded_commit(group_id, &plan, |this| {
            let provider = &this.provider;
            let signer = &this.signer;
            let group = this.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            group
                .commit_builder()
                // The rename carries exactly what the person asked for, and
                // nothing somebody else queued: a deliberate act should carry
                // exactly what the person asked for.
                .consume_proposal_store(false)
                .propose_group_context_extensions(extensions)
                .map_err(mls_err)?
                .load_psks(provider.storage())
                .map_err(mls_err)?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(group_context_build_error)?
                .stage_commit(provider)
                .map_err(mls_err)
        })?;
        self.refuse_own_commit_receivers_would_refuse(group_id)?;

        let commit = bundle.commit().to_bytes().map_err(mls_err)?;
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        // STAGED, NOT MERGED. See §The commit lifecycle.
        Ok(CommitBundle {
            commit,
            welcome: None,
            epoch: group.epoch().as_u64() + 1,
        })
    }

    /// Whether this device's own leaf in `group_id` is missing a capability
    /// this build requires every leaf to advertise (`PEACHY_GROUP_CONTEXT_TYPES`).
    ///
    /// True for a leaf seated by a build that predates `peachy_group_meta`.
    /// Such a leaf blocks every member from renaming the group — OpenMLS
    /// refuses a `GroupContextExtensions` proposal unless every leaf supports
    /// it — and the cure is a leaf renewal, which is why
    /// [`Self::leaf_credential_expiring`] and [`Self::credential_refresh_due`]
    /// both answer true for it: the renewal path every client already runs
    /// before a send and at app start or foreground is the one that upgrades
    /// it, with no client change.
    pub fn leaf_capabilities_stale(&self, group_id: &[u8]) -> Result<bool> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if !group.is_active() {
            return Ok(false);
        }
        let own = group.own_leaf_index();
        let Some(leaf) = group.public_group().leaf(own) else {
            return Err(Error::NotAMember);
        };
        let advertised = leaf.capabilities().extensions();
        Ok(PEACHY_GROUP_CONTEXT_TYPES
            .iter()
            .any(|code| !advertised.contains(&ExtensionType::Unknown(*code))))
    }

    // ---- The commit lifecycle -----------------------------------------------

    /// The delivery service TOOK this group's staged commit: adopt the epoch.
    ///
    /// Returns the epoch the group is now in. Idempotent only in the sense that
    /// it is [`Error::InvalidArgument`] to call it with nothing staged — a
    /// caller asking to merge is a caller who believes it built something.
    ///
    /// The merge, and not the stage, is what moves the group to the new
    /// epoch, and that ordering is the whole point of the split: the stage
    /// was committed as a PENDING commit beside the epoch the group is in,
    /// and the durable state moves to the new epoch only here, after the
    /// server has agreed that the new epoch is the group's.
    pub fn merge_pending_commit(&mut self, group_id: &[u8]) -> Result<u64> {
        self.synced(|client| client.merge_pending_commit_now(group_id))
    }

    fn merge_pending_commit_now(&mut self, group_id: &[u8]) -> Result<u64> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        let Some(staged) = group.pending_commit() else {
            return Err(Error::invalid("this group has no staged commit to merge"));
        };
        // A commit of this device's that carries an update path puts a new
        // leaf of its own into the tree: a rotation, whatever else it did.
        let rotated = staged.update_path_leaf_node().is_some();
        let removed: Vec<u32> = staged
            .remove_proposals()
            .map(|proposal| proposal.remove_proposal().removed().u32())
            .collect();
        let removed_actors = Self::actors_at_leaves(
            &self.identity_provider,
            &self.identity.actor_id,
            group,
            &removed,
        );
        let seated: Vec<PeachyIdentity> = staged
            .add_proposals()
            .filter_map(|proposal| {
                let leaf = proposal.add_proposal().key_package().leaf_node();
                self.identity_provider
                    .validate_seated_credential(
                        leaf.credential(),
                        leaf.signature_key().as_slice(),
                        i64::MAX,
                    )
                    .ok()
            })
            .map(|(identity, _)| identity)
            .collect();
        // The leaves it adds, for the record of the epoch it leaves; unknown
        // when one did not read.
        let added_next = (seated.len() == staged.add_proposals().count()).then(|| {
            seated
                .iter()
                .map(|identity| device_key_digest(&identity.device_key))
                .collect::<Vec<_>>()
        });
        // Whoever the commit seats has not left (`NS_DEPARTED`).
        let returned: Vec<String> = seated.iter().map(|id| id.actor_id.clone()).collect();
        // This account's other devices this device itself seats: its own
        // add is evidence of each one's key for the new-device notice
        // (`own_devices.rs` §What the new-device notice is told).
        let seated_siblings: Vec<(String, Vec<u8>)> = seated
            .into_iter()
            .filter(|identity| {
                identity.actor_id == self.identity.actor_id
                    && identity.device_id != self.identity.device_id
            })
            .map(|identity| (identity.device_id, identity.device_key.to_vec()))
            .collect();
        // Judged BEFORE the merge, while the commit's own adds are not yet
        // leaves this device would trust (`own_devices.rs` §A seat this
        // device made on no verdict).
        let (seated_siblings, seated_on_no_verdict) = self.split_own_adds(seated_siblings);
        // What this device's own commit does to the steward key the group
        // counts, judged on the state before the merge (`StewardMerge`).
        let own_actor = self.identity.actor_id.clone();
        if let Some(merge) = self.steward_merge_of(group_id, &own_actor, true)? {
            self.steward_merges.insert(group_id.to_vec(), merge);
        }
        // The epoch this commit leaves: an envelope sealed in it, and the
        // commit's own envelope, are sealed under it after the merge.
        if let Err(err) = self.note_envelope_epoch(group_id, added_next) {
            log::warn!("peachy-mls: could not keep the epoch's envelope secret: {err}");
        }
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(mls_err)?;
        let epoch = group.epoch().as_u64();
        self.saved_stages.remove(group_id);
        // Merged: the digest has nothing left to match.
        if let Err(err) = self
            .provider
            .peachy_storage()
            .forget_staged_commit(group_id)
        {
            log::warn!("peachy-mls: could not drop a merged commit's digest: {err}");
        }
        let departed = Self::without_a_leaf(&self.identity_provider, group, removed_actors);
        self.note_departed(group_id, &departed)?;
        for actor in &returned {
            self.provider
                .peachy_storage()
                .clear_departed(group_id, actor)?;
        }
        // A merge follows the delivery service's answer that it took the
        // commit, or a head that names it (`settle_saved_commit`): the copy
        // is the group's head ([`Self::confirm_head`]), and the group's own
        // handle took it there ([`Self::head_rolled_back`]).
        self.note_head_confirmed(group_id)?;
        self.note_copy_epoch(group_id)?;
        if let Some(group) = self.groups.get(group_id) {
            self.provider
                .peachy_storage()
                .vouch_head_epoch(group_id, group.epoch().as_u64())?;
        }
        self.provider
            .peachy_storage()
            .set_own_commits_refused(group_id, 0)?;
        // The commit is merged: a store that cannot take the note must not
        // make it look refused.
        if let Err(err) = self.note_own_sibling_keys_on_evidence(&seated_siblings) {
            log::warn!("peachy-mls: could not record a sibling's key: {err}");
        }
        if let Err(err) = self.note_seats_outside_the_gate(&seated_on_no_verdict) {
            log::warn!("peachy-mls: could not record an own seat made on no verdict: {err}");
        }
        if rotated {
            self.note_fresh_leaf(group_id)?;
        }
        // The previous epoch's secrets were replaced; erased too, so a store
        // copied from this device after the merge cannot derive them.
        self.flushed_and_erased(epoch)
    }

    /// The delivery service REFUSED this group's staged commit: drop the branch.
    ///
    /// The commit was built against an epoch the group has already left, so the
    /// state it would have produced is on a branch no other member will ever
    /// walk. MLS has no merge: the only correct move is to throw it away and
    /// replay the server's order, which the caller does next.
    ///
    /// Not calling this is the bug this method exists for. A device that kept
    /// the branch would go on encrypting at an epoch nobody else is in — every
    /// message unreadable by every member, with `is_active` still answering
    /// true and nothing anywhere going red.
    ///
    /// Safe to call with nothing staged, unlike [`Self::merge_pending_commit`]:
    /// this one is the error path, and an error path that can itself fail for
    /// being called twice is an error path callers get wrong.
    ///
    /// Erases as well as flushes: the stage was committed when it was made
    /// (§The commit lifecycle), so the group's stored state held the refused
    /// branch's next-epoch secrets, and on SQLite the write-ahead log still
    /// would after a plain flush.
    ///
    /// **A saved commit is not this call's to clear**
    /// ([`Self::has_saved_commit`]): it is left in place and this answers
    /// `Ok`. Every caller of this door clears a stage of its own run, and
    /// while a saved commit waits the core refuses to stage another; a caller
    /// clearing on that refusal's error path would otherwise throw away a
    /// commit the delivery service may have taken.
    pub fn clear_pending_commit(&mut self, group_id: &[u8]) -> Result<()> {
        self.synced(|client| {
            if client.has_saved_commit(group_id)? {
                log::info!(
                    "peachy-mls: a saved commit is left for the group's head to settle, not cleared"
                );
                return Ok(());
            }
            client.clear_stage(group_id)
        })
    }

    fn clear_stage(&mut self, group_id: &[u8]) -> Result<()> {
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        let had_stage = group.pending_commit().is_some();
        group
            .clear_pending_commit(self.provider.storage())
            .map_err(|err| Error::Mls(format!("could not clear the staged commit: {err}")))?;
        self.saved_stages.remove(group_id);
        self.provider
            .peachy_storage()
            .forget_staged_commit(group_id)?;
        if had_stage {
            self.note_own_commit_refused(group_id)?;
        }
        self.flushed_and_erased(())
    }

    /// Count a commit of this device's own in `group_id` the delivery
    /// service did not take. A copy no head has matched yet is confirmed by
    /// the device's own merged commit, and the delivery service can refuse
    /// every one of those, which also stops this device's leaf rotation
    /// there. After [`OWN_COMMITS_REFUSED_CONTEST`] refusals in a row with
    /// none taken, such a copy is contested ([`Self::contest_copy`]), so the
    /// client says so rather than nothing. A merge resets the count.
    fn note_own_commit_refused(&self, group_id: &[u8]) -> Result<()> {
        let storage = self.provider.peachy_storage();
        let refused = storage.own_commits_refused(group_id)?.saturating_add(1);
        storage.set_own_commits_refused(group_id, refused)?;
        if refused >= OWN_COMMITS_REFUSED_CONTEST {
            log::warn!(
                "peachy-mls: the delivery service refused this device's last {refused} commits in \
                 a group"
            );
            self.contest_copy(group_id)?;
        }
        Ok(())
    }

    /// Whether this group is holding a staged commit awaiting a verdict.
    pub fn has_pending_commit(&self, group_id: &[u8]) -> Result<bool> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        Ok(group.pending_commit().is_some())
    }

    // ---- A commit saved across a restart -------------------------------------
    //
    // A stage is committed when it is made (§The commit lifecycle), so a
    // process that dies, or is killed, while its commit waits on the delivery
    // service leaves that commit on disk with no verdict. The next open keeps
    // it and writes nothing for it; the caller settles it against the group's
    // head, in a short write of its own, before it processes anything for
    // the group. Until then the group sends nothing (OpenMLS builds no
    // message over a pending commit) and no other commit is staged in it.

    /// Whether this group holds a commit found staged at open and not settled
    /// yet. A stage made by this run is not one: its verdict comes back to
    /// the call that submitted it.
    pub fn has_saved_commit(&self, group_id: &[u8]) -> Result<bool> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        Ok(self.saved_stages.contains(group_id) && group.pending_commit().is_some())
    }

    /// [`Error::SettleFirst`] when this group holds a saved commit: what
    /// drops or replaces the group ([`Self::forget_group`], a Welcome taking
    /// its place) would drop a commit the delivery service may have taken.
    fn refuse_unsettled(&self, group_id: &[u8]) -> Result<()> {
        let saved = self.groups.get(group_id).is_some_and(|group| {
            self.saved_stages.contains(group_id) && group.pending_commit().is_some()
        });
        if saved {
            return Err(Error::SettleFirst);
        }
        Ok(())
    }

    /// Whether `message` is the very commit saved in this group.
    fn is_saved_commit_echo(&self, group_id: &[u8], message: &[u8]) -> Result<bool> {
        if !self.has_saved_commit(group_id)? {
            return Ok(false);
        }
        let digest: [u8; 32] = sha2::Sha256::digest(message).into();
        let staged = self.provider.peachy_storage().staged_commit(group_id)?;
        Ok(staged.as_deref() == Some(digest.as_slice()))
    }

    /// Settle a saved commit ([`Self::has_saved_commit`]) by the group's head
    /// as the delivery service reports it (`FetchConversationHead` for
    /// [`crate::envelope::group_handle`] of the id): its epoch and the
    /// SHA-256 of that epoch's send key ([`SEND_KEY_LABEL`]).
    ///
    /// - The head is the epoch the commit makes, under the send key it
    ///   makes: the delivery service took it. Merged, as the answer to its
    ///   submit would have merged it: [`SavedCommit::Merged`].
    /// - The head is the group's own epoch, or the commit's epoch under
    ///   another send key: it was not taken, or another commit was. Cleared:
    ///   [`SavedCommit::Cleared`].
    /// - The head is past the commit's epoch: the head alone cannot say whose
    ///   commit made the epoch after this one. Kept: [`SavedCommit::Waiting`].
    ///   The commit door decides it as the device catches up: its own echo
    ///   merges it (the delivery service hands a commit on only once it took
    ///   it, and the echo is matched to the stage by the SHA-256 of the
    ///   commit's bytes, kept beside the stage), and another member's commit
    ///   at its epoch replaces it.
    ///
    /// A caller that cannot read the head calls nothing and keeps the commit:
    /// the verdict is unknown, and a device that cleared it then would need a
    /// rejoin if it was taken. [`Error::InvalidArgument`] when no saved commit
    /// waits in the group. Flushed on every outcome that wrote.
    pub fn settle_saved_commit(
        &mut self,
        group_id: &[u8],
        head_epoch: u64,
        head_verifier: &[u8],
    ) -> Result<SavedCommit> {
        self.synced(|client| client.settle_saved_commit_now(group_id, head_epoch, head_verifier))
    }

    fn settle_saved_commit_now(
        &mut self,
        group_id: &[u8],
        head_epoch: u64,
        head_verifier: &[u8],
    ) -> Result<SavedCommit> {
        if !self.has_saved_commit(group_id)? {
            self.saved_stages.remove(group_id);
            return Err(Error::invalid("no saved commit waits in this group"));
        }
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        let next = group.epoch().as_u64().saturating_add(1);
        if head_epoch > next {
            return Ok(SavedCommit::Waiting);
        }
        if head_epoch == next {
            // A commit that removes this device exports nothing: it cannot be
            // matched, and is cleared below.
            let made = group.pending_commit().and_then(|staged| {
                staged
                    .export_secret(self.provider.crypto(), SEND_KEY_LABEL, group_id, 32)
                    .ok()
                    .map(Zeroizing::new)
            });
            if let Some(secret) = made {
                let verifier: [u8; 32] = sha2::Sha256::digest(&secret[..]).into();
                if verifier.as_slice() == head_verifier {
                    log::warn!("peachy-mls: a saved commit is the group's head — merging it");
                    self.merge_pending_commit(group_id)?;
                    return Ok(SavedCommit::Merged);
                }
            }
        }
        log::info!("peachy-mls: a saved commit is not the group's head — clearing it");
        self.clear_stage(group_id)?;
        Ok(SavedCommit::Cleared)
    }

    // ---- Falling behind the delivery service's retention window -------------

    /// Whether this group's local state is older than what the server still
    /// holds.
    ///
    /// `server_oldest_epoch` is the epoch of the oldest commit the delivery
    /// service has NOT swept (docs/delivery.md §Retention). A device
    /// sitting at
    /// epoch E catches up by applying the commit that was BUILT at epoch E —
    /// so if E is below the oldest epoch the server still has, that commit is
    /// gone, and no amount of fetching will produce it.
    ///
    /// There is no cryptographic recovery from this and there is not meant to
    /// be: the ratchet moved on without this device, every epoch secret since
    /// is derived from material it never saw, and a server that could hand back
    /// the old epochs would be a server that could read the group. The answer
    /// is [`Self::forget_group`] and a fresh Welcome minted by a live member's
    /// [`Self::replace_member`].
    ///
    /// Equality is NOT behind: a device at exactly the oldest retained epoch
    /// has the one commit it needs.
    pub fn is_behind(&self, group_id: &[u8], server_oldest_epoch: u64) -> Result<bool> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        Ok(group.epoch().as_u64() < server_oldest_epoch)
    }

    /// Whether failing to apply `message` leaves this device STRANDED in the
    /// group: off the ratchet for good, exactly as if it had slept past the
    /// retention window (docs/delivery.md §A commit this device
    /// cannot apply).
    ///
    /// Asked AFTER [`Self::process_commit`] has refused a commit, and answered
    /// from the message's own framing, this device's own epoch and what the
    /// refusal learned — never from the label the delivery service put on
    /// the stream entry. True exactly when the message is THE commit at this
    /// device's epoch, the commit door refused it last, and it had opened and
    /// verified first: a member of the group at this epoch built it, the
    /// delivery service accepts one commit per epoch, and this device cannot
    /// apply it — a commit its policy refused that the rest of the group
    /// merged. Nothing after it can apply either.
    ///
    /// **A commit that did not open never strands.** Its group id, epoch and
    /// content type are framing, readable and writable by anyone who holds
    /// the group id, a removed member included; if failing to open one
    /// stranded a device, such a person could make every member forget the
    /// group at once, leaving nobody to seat anybody again. So a commit that
    /// would not open, at this device's epoch or above it, answers false, and
    /// the caller asks the group's head instead (docs/delivery.md
    /// §A commit this device cannot apply). The head is what tells a device
    /// whose copy forked, or that fell behind (this device's own accepted
    /// commit whose staged copy is gone, `mls/core/tests/commit_race.rs`),
    /// from bytes that were never a commit of this group.
    ///
    /// False too for everything a device can safely skip: a commit from an
    /// epoch it has already left (a duplicate, a replay from the start of the
    /// stream), a proposal or an application message, bytes that will not
    /// even parse as a group message, and a group this device holds no
    /// active state for — there is nothing to strand there.
    ///
    /// A caller must still hold back on a transient failure
    /// ([`Error::Storage`]) rather than ask this: a locked database is not a
    /// lost epoch.
    pub fn commit_strands(&self, group_id: &[u8], message: &[u8]) -> Result<bool> {
        let Some(group) = self.groups.get(group_id) else {
            return Ok(false);
        };
        if !group.is_active() {
            return Ok(false);
        }
        // A HELD group strands nobody: the device waits for the steward's
        // repair or veto ([`Self::group_hold`]).
        if self.group_hold(group_id)?.is_some() {
            return Ok(false);
        }
        // A carried commit is judged by its commit; the digest below is of
        // the whole entry, as the commit door kept it.
        let Ok(carried) = crate::carried_commit::split_carried(message) else {
            return Ok(false);
        };
        let Ok(incoming) = MlsMessageIn::tls_deserialize_exact(carried.commit) else {
            return Ok(false);
        };
        let Ok(protocol) = incoming.try_into_protocol_message() else {
            return Ok(false);
        };
        if protocol.group_id().as_slice() != group_id {
            return Ok(false);
        }
        if protocol.content_type() != openmls::prelude::ContentType::Commit
            || protocol.epoch().as_u64() != group.epoch().as_u64()
        {
            return Ok(false);
        }
        let digest: [u8; 32] = sha2::Sha256::digest(message).into();
        Ok(matches!(
            self.refused_commits.get(group_id),
            Some((refused, true)) if *refused == digest
        ))
    }

    /// What the commit door just did with `message`, for
    /// [`Self::commit_strands`]: a refusal is kept with whether the commit
    /// opened and verified before it was refused; anything else clears it.
    fn note_commit_refusal(&mut self, group_id: &[u8], message: &[u8], refused: bool) {
        if refused {
            let digest: [u8; 32] = sha2::Sha256::digest(message).into();
            self.refused_commits
                .insert(group_id.to_vec(), (digest, self.last_refusal_authenticated));
        } else {
            self.refused_commits.remove(group_id);
        }
    }

    /// Hand in the SEALED STAMP the delivery service attached to the commit
    /// about to go through [`Self::process_commit`] for `group_id`
    /// (`MailboxEnvelope.commit_stamp`; docs/delivery.md §The
    /// sealed stamp). Kept in memory for that one commit; an empty stamp
    /// hands in nothing.
    pub fn note_commit_stamp(&mut self, group_id: &[u8], stamp: &[u8]) {
        if stamp.is_empty() {
            self.pending_stamps.remove(group_id);
        } else {
            self.pending_stamps
                .insert(group_id.to_vec(), stamp.to_vec());
        }
    }

    /// What the commit door found checking the last commit it merged in
    /// `group_id` against its sealed stamp, once: taken, it is gone. `None`
    /// when no commit has merged since the last take. In this build a
    /// caller only alerts on it ([`crate::steward::CommitCheck::alerts`]).
    pub fn take_commit_check(&mut self, group_id: &[u8]) -> Option<crate::steward::CommitCheck> {
        self.commit_checks.remove(group_id)
    }

    /// What the stamp check needs from the copy before the commit merges.
    /// `None` when the copy cannot answer (an exporter failing included):
    /// the stamp is evidence, so the door then reads it as unread rather
    /// than failing the commit.
    fn stamp_inputs(&self, group_id: &[u8]) -> Option<StampInputs> {
        let group = self.groups.get(group_id)?;
        if !group.is_active() {
            return None;
        }
        let crypto = self.provider.crypto();
        let send_key = group
            .export_secret(crypto, SEND_KEY_LABEL, group_id, 32)
            .ok()?;
        let mac_key = group
            .export_secret(crypto, crate::steward::COMMIT_MAC_LABEL, group_id, 32)
            .ok()?;
        let steward = group_meta_from_context(group.extensions())
            .and_then(|meta| crate::steward::steward_key_of_meta(&meta));
        Some(StampInputs {
            epoch: group.epoch().as_u64(),
            send_key: Zeroizing::new(send_key),
            mac_key: Zeroizing::new(mac_key),
            steward,
        })
    }

    /// The receiver's rule (docs/delivery.md §The sealed stamp): the
    /// verifier the stamp says the submitter named (S) against the one the
    /// merged commit produces (V), the MAC, and the steward key.
    fn check_stamp(
        &self,
        group_id: &[u8],
        entry: &[u8],
        stamp: Option<&[u8]>,
        before: Option<StampInputs>,
        merged: &CommitOutcome,
    ) -> Result<crate::steward::CommitCheck> {
        use crate::steward::{CommitCheck, MacVerdict, StampVerdict, StewardVerdict};
        let unread = |stamp| CommitCheck {
            epoch: merged.epoch.saturating_sub(1),
            stamp,
            blame: None,
            mac: MacVerdict::Unread,
            steward: StewardVerdict::Unread,
        };
        let (Some(sealed), Some(before)) = (stamp, before) else {
            return Ok(unread(match stamp {
                None => StampVerdict::Absent,
                Some(_) => StampVerdict::Unjudged,
            }));
        };
        let at = before.epoch;
        let Ok(opened) = crate::steward::open_stamp(&before.send_key, at, sealed) else {
            return Ok(unread(StampVerdict::Unopened));
        };
        let mac = match &opened.mac {
            None => MacVerdict::Missing,
            Some(mac) => {
                if crate::steward::commit_mac_holds(
                    &before.mac_key,
                    &opened.next_verifier,
                    at,
                    entry,
                    mac,
                ) {
                    MacVerdict::Valid
                } else {
                    MacVerdict::Invalid
                }
            }
        };
        // The stamp names the key the handle holds FROM this commit on, so it
        // is compared with the meta the commit leaves (a rotation changes
        // both together); the meta it was built on only for a copy the
        // commit removed.
        let after = self
            .groups
            .get(group_id)
            .filter(|group| group.is_active() && !merged.removed_self)
            .map(|group| {
                group_meta_from_context(group.extensions())
                    .and_then(|meta| crate::steward::steward_key_of_meta(&meta))
            })
            .unwrap_or(before.steward);
        let steward = match (after, opened.steward_pub) {
            (None, None) => StewardVerdict::None,
            (a, b) if a == b => StewardVerdict::Match,
            _ => StewardVerdict::Mismatch,
        };
        let real = if merged.removed_self {
            None
        } else {
            self.verifier_of_held(group_id)?
        };
        let (verdict, blame) = match real {
            None => (StampVerdict::Unjudged, None),
            Some(v) if v == opened.next_verifier => (StampVerdict::Match, None),
            Some(_) if mac == MacVerdict::Valid => {
                (StampVerdict::Blame, Some(merged.sender.actor_id.clone()))
            }
            Some(_) => (StampVerdict::Repair, None),
        };
        Ok(CommitCheck {
            epoch: at,
            stamp: verdict,
            blame,
            mac,
            steward,
        })
    }

    /// THE GROUP HOLD of `group_id` ([`crate::steward::GroupHold`]), when it
    /// holds now: not lapsed, and the copy still at the epoch it was held at.
    /// `None` for a group never held, or whose hold is behind it.
    pub fn group_hold(&self, group_id: &[u8]) -> Result<Option<crate::steward::GroupHold>> {
        // This core honors no steward, so no hold holds ([`crate::steward::STEWARD_READS`]).
        if !self.honors_stewards {
            return Ok(None);
        }
        let Some(group) = self.groups.get(group_id) else {
            return Ok(None);
        };
        let Some(hold) = self.provider.peachy_storage().group_hold(group_id)? else {
            return Ok(None);
        };
        let now = self.identity_provider.now_unix();
        Ok(hold.holds(now, group.epoch().as_u64()).then_some(hold))
    }

    /// Hold `group_id` for its steward's repair or veto. Only a group this
    /// device counts as enrolled ([`Self::enrolled_steward_key`]) is ever
    /// held: for any other this does nothing and answers false, so the group
    /// behaves as it always did. A hold already holding keeps its start and
    /// its cap, and answers true.
    ///
    /// AT MOST ONE HOLD AN EPOCH: a hold that lapsed (at its cap, by
    /// [`Self::release_hold`], or by a clock set back) is kept, and another
    /// trigger at the same epoch answers false, so the caller falls back to
    /// rejoining as it always did. Only a copy that has moved to another
    /// epoch may be held again.
    ///
    /// A REPEAT HOLD: a copy forgotten since its last full hold began (it
    /// lapsed and rejoined) is held within a day of that start only for
    /// [`crate::steward::repeat_hold_cap`] (ten minutes, then five, then two
    /// and a half), and after those not at all
    /// ([`crate::steward::HOLD_REPEAT_SECONDS`]). A repeat the copy settles
    /// by merging leaves its record at another epoch, and still counts: the
    /// rejoin is kept apart from the copy's records, so the next stall inside
    /// the day is the next repeat, never a full hold again.
    pub fn enter_hold(
        &mut self,
        group_id: &[u8],
        reason: crate::steward::HoldReason,
    ) -> Result<bool> {
        self.synced(|client| {
            let Some(group) = client.groups.get(group_id) else {
                return Ok(false);
            };
            if !group.is_active() {
                return Ok(false);
            }
            // While this core honors no steward, an enrolled group is held as
            // one never enrolled is: not at all ([`crate::steward::STEWARD_READS`]).
            if !client.honors_stewards {
                return Ok(false);
            }
            if client.enrolled_steward_key(group_id, group)?.is_none() {
                return Ok(false);
            }
            let epoch = group.epoch().as_u64();
            let now = client.identity_provider.now_unix();
            let storage = client.provider.peachy_storage();
            // Which repeat of the day this hold is, if it is one.
            let mut repeat = None;
            let kept = storage.group_hold(group_id)?;
            if let Some(kept) = kept {
                if kept.epoch == epoch {
                    let holds = kept.holds(now, epoch);
                    if !holds {
                        log::warn!(
                            "peachy-mls: a group's hold at epoch {epoch} has lapsed; it is not \
                             held again there"
                        );
                        // Lapsed for good: a clock set back and then forward
                        // again does not bring it back.
                        if kept.until > kept.since {
                            let mut lapsed = kept;
                            lapsed.until = lapsed.since;
                            storage.set_group_hold(group_id, Some(&lapsed))?;
                        }
                    }
                    return Ok(holds);
                }
            }
            if let Some(mut started) = storage.hold_started(group_id)? {
                // A start later than now was written by a clock running
                // ahead: counted from now, and kept so, or the clock coming
                // back would stretch the day to however far ahead it ran.
                if started > now {
                    started = now;
                    storage.set_hold_started(group_id, started)?;
                }
                // A full hold began not long ago and the copy was forgotten
                // since with a hold on record (it lapsed and rejoined): no
                // hold on record now, or the mark that outlives the record
                // of a repeat hold settled by a merge since. Within the day
                // (`HOLD_REPEAT_SECONDS`) only a shorter repeat hold, and
                // once those are spent none; a settled repeat never makes
                // the next one full.
                let rejoined = kept.is_none() || storage.hold_rejoined(group_id)?;
                if rejoined && now < started.saturating_add(crate::steward::HOLD_REPEAT_SECONDS) {
                    let next = storage.hold_repeats(group_id)?.saturating_add(1);
                    let Some(cap) = crate::steward::repeat_hold_cap(next) else {
                        log::warn!(
                            "peachy-mls: a group whose holds ended in rejoins has spent its \
                             repeat holds for the day; it is not held"
                        );
                        return Ok(false);
                    };
                    repeat = Some((next, cap));
                }
            }
            let hold = match repeat {
                Some((_, cap)) => crate::steward::GroupHold::with_cap(epoch, now, cap, reason),
                None => crate::steward::GroupHold::new(epoch, now, reason),
            };
            log::warn!(
                "peachy-mls: holding a group at epoch {} for its steward ({:?}, {}s)",
                hold.epoch,
                reason,
                hold.until.saturating_sub(hold.since)
            );
            storage.set_group_hold(group_id, Some(&hold))?;
            match repeat {
                // A repeat keeps the day's start: the day runs from the full
                // hold, however many repeats follow it.
                Some((next, _)) => storage.set_hold_repeats(group_id, next)?,
                None => {
                    storage.set_hold_started(group_id, hold.since)?;
                    storage.set_hold_repeats(group_id, 0)?;
                    storage.set_hold_rejoined(group_id, false)?;
                }
            }
            Ok(true)
        })
    }

    /// Release the hold of `group_id`, if any: it lapses now, and stays on
    /// record so the copy is not held again at this epoch.
    pub fn release_hold(&mut self, group_id: &[u8]) -> Result<()> {
        self.synced(|client| {
            let storage = client.provider.peachy_storage();
            let Some(mut hold) = storage.group_hold(group_id)? else {
                return Ok(());
            };
            hold.until = hold.since;
            Ok(storage.set_group_hold(group_id, Some(&hold))?)
        })
    }

    /// What a commit entry's VETO FRAME means to this device
    /// ([`crate::steward::VetoVerdict`]): checked against the steward key the
    /// meta named at the vetoed commit's epoch, now or as kept for seven days.
    /// For the drain's look-ahead: a later entry that vetoes the commit at
    /// this device's epoch lets it skip that commit, and one that vetoes a
    /// commit it already merged sends it to rejoin at once. A veto of an
    /// earlier epoch that the copy cannot judge under a key it kept for that
    /// epoch (its successor more than 63 epochs back or before its seat, or
    /// no key kept there) asks for the head to be read at once (`CheckHead`),
    /// signed or not: the copy may be on the vetoed branch, and the fork
    /// check ([`Self::head_rolled_back`]) says.
    pub fn judge_veto(&self, group_id: &[u8], entry: &[u8]) -> Result<crate::steward::VetoVerdict> {
        let Ok(carried) = crate::carried_commit::split_carried(entry) else {
            return Ok(crate::steward::VetoVerdict::None);
        };
        let Some(signed) = carried.veto else {
            return Ok(crate::steward::VetoVerdict::None);
        };
        self.veto_verdict(group_id, signed, carried.vetoed)
    }

    fn veto_verdict(
        &self,
        group_id: &[u8],
        signed: &[u8],
        vetoed: &[u8],
    ) -> Result<crate::steward::VetoVerdict> {
        use crate::steward::VetoVerdict;
        let Ok(veto) = crate::steward::SignedVeto::from_bytes(signed) else {
            return Ok(VetoVerdict::None);
        };
        if veto.handle != crate::envelope::group_handle(group_id)? {
            return Ok(VetoVerdict::None);
        }
        let Some(group) = self.groups.get(group_id) else {
            return Ok(VetoVerdict::None);
        };
        if !group.is_active() {
            return Ok(VetoVerdict::None);
        }
        let epoch = group.epoch().as_u64();
        let storage = self.provider.peachy_storage();
        if veto.epoch > epoch {
            return Ok(VetoVerdict::None);
        }
        // WHILE THIS CORE HONORS NO STEWARD ([`crate::steward::STEWARD_READS`]), a
        // veto is judged as in a group never enrolled: at this copy's epoch
        // it skips nothing, and of an earlier one it only asks for the head
        // to be read (the fork check), never sends the copy to rejoin on the
        // frame's word.
        if !self.honors_stewards {
            return Ok(if veto.epoch == epoch {
                VetoVerdict::None
            } else {
                VetoVerdict::CheckHead
            });
        }
        // Only a key the group is ENROLLED under signs a veto this device
        // acts on beyond a head read ([`Self::enrolled_steward_key`]): a
        // member who wrote `stw` into the meta has no stamp naming it. The
        // kept keys of earlier epochs were recorded under the same rule.
        if veto.epoch == epoch {
            let Some(key) = self.enrolled_steward_key(group_id, group)? else {
                return Ok(VetoVerdict::None);
            };
            return Ok(if veto.verify(&key, vetoed) {
                VetoVerdict::SkipVetoed
            } else {
                VetoVerdict::None
            });
        }
        let kept = storage.copy_verifiers(group_id)?;
        // The epoch after the vetoed commit's, where the copy would hold
        // `vetoed_next` had it merged it; below every kept epoch, nothing
        // here says.
        let successor_kept = kept
            .first()
            .is_some_and(|(oldest, _)| veto.epoch + 1 >= *oldest);
        let kept_key = storage
            .steward_keys(group_id)?
            .into_iter()
            .find(|(at, _, _)| *at == veto.epoch)
            .map(|(_, _, key)| key);
        let Some(key) = kept_key.filter(|_| successor_kept) else {
            // This copy cannot tell, under a key it kept, whether it merged
            // the vetoed commit: too far back, or before its seat (a device
            // seated on the vetoed branch, the vetoed commit's own Welcome
            // included), or before any stamp enrolled it. Any well-formed
            // frame for this handle asks for the head to be read, signed or
            // not: that read is the fork check, rate-limited, which anybody
            // holding the group id can already prompt with a commit that
            // will not open, and it never rejoins on the frame's word.
            return Ok(VetoVerdict::CheckHead);
        };
        if !veto.verify(&key, vetoed) {
            return Ok(VetoVerdict::None);
        }
        let merged_vetoed = kept
            .iter()
            .any(|(at, verifier)| *at == veto.epoch + 1 && *verifier == veto.vetoed_next);
        Ok(if merged_vetoed {
            VetoVerdict::RejoinNow
        } else {
            VetoVerdict::None
        })
    }

    /// Judge a REPAIR NOTICE lane frame ([`crate::steward::RepairNotice`])
    /// from `sender` (the MLS sender's actor id, as the message door
    /// authenticated it) against the verifier this device's copy had at its
    /// epoch. Only an ADMIN repairs a head, so a notice from anyone the
    /// group's meta does not name in `adm` is not one: `Unjudged`, and
    /// nothing held. An inconsistent notice from an admin holds the group
    /// (only one this device counts as enrolled, and at most once an epoch:
    /// [`Self::enter_hold`]). `Unjudged` too for anything that is not a
    /// repair notice, and for an epoch this device has no verifier of.
    pub fn check_repair_notice(
        &mut self,
        group_id: &[u8],
        sender: &str,
        wire: &[u8],
    ) -> Result<crate::steward::RepairNoticeVerdict> {
        use crate::steward::{HoldReason, RepairNotice, RepairNoticeVerdict};
        let Some(notice) = RepairNotice::parse(wire) else {
            return Ok(RepairNoticeVerdict::Unjudged);
        };
        let from_admin = self
            .groups
            .get(group_id)
            .filter(|group| group.is_active())
            .and_then(|group| group_meta_from_context(group.extensions()))
            .is_some_and(|meta| crate::steward::meta_names_admin(&meta, sender));
        if !from_admin {
            log::warn!(
                "peachy-mls: a repair notice came from a member who is not an admin; not judged"
            );
            return Ok(RepairNoticeVerdict::Unjudged);
        }
        let own = self
            .provider
            .peachy_storage()
            .copy_verifiers(group_id)?
            .into_iter()
            .find(|(at, _)| *at == notice.epoch)
            .map(|(_, v)| v);
        let verdict = notice.judge(own.as_ref());
        if verdict == RepairNoticeVerdict::Inconsistent {
            log::warn!(
                "peachy-mls: a repair notice names a verifier this device's copy did not have at \
                 epoch {}",
                notice.epoch
            );
            self.enter_hold(group_id, HoldReason::FalseRepair)?;
        }
        Ok(verdict)
    }

    /// Open the head log's copy of the commit built at this device's epoch
    /// (FetchCommitAt, not part of this specification) with the
    /// epoch's send key: the commit envelope as it was placed, which the
    /// caller opens and takes through the commit door like any other.
    pub fn open_fetched_commit(&self, group_id: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if !group.is_active() {
            return Err(Error::NoSuchGroup);
        }
        let send_key = Zeroizing::new(
            group
                .export_secret(self.provider.crypto(), SEND_KEY_LABEL, group_id, 32)
                .map_err(mls_err)?,
        );
        crate::steward::open_log_copy(&send_key, group.epoch().as_u64(), sealed)
    }

    /// THE MESSAGE DOOR: one incoming group message, for an entry that arrived as a
    /// message (envelope kind [`crate::envelope::ENVELOPE_KIND_MESSAGE`], or a
    /// push). An application message goes through, and so does a LEAVE: a
    /// standalone Remove of a leaf of its sender's own person, which is
    /// queued ([`Incoming::ProposalQueued`]) for
    /// [`Client::commit_proposed_leaves`].
    ///
    /// Any other proposal, and a leave this device cannot queue (refused by
    /// the rules, from a lapsed leaf, from an epoch the group has left), is
    /// refused with [`Error::WrongDoor`], as every proposal was before
    /// leaves: a caller drops it unread and draws nothing for it. A
    /// transient store failure stays [`Error::Storage`].
    ///
    /// A commit here is refused with [`Error::WrongDoor`] before the engine
    /// reads it. A commit is taken only through
    /// [`Client::process_commit`], from an entry the arbiter ordered: one
    /// commit per epoch, delivered as `MAILBOX_KIND_COMMIT`, and run through
    /// each client's commit path — the roster rows, the account-key
    /// comparison, the group-meta re-read. A commit merged here would move
    /// the epoch and the roster with none of that, and a member could hand
    /// different commits for one epoch to different devices without the
    /// arbiter seeing either.
    ///
    /// The kind is read off the message's own framing, which a
    /// `PrivateMessage` carries in the clear, so a refusal spends nothing:
    /// the group, its epoch and its ratchets are as they were.
    ///
    /// An application message this device already opened, the same bytes
    /// handed over again, is refused with [`Error::Duplicate`] before the
    /// engine reads it ([`Self::process_application`]).
    ///
    /// The second the delivery service received the message is not known
    /// here, which [`Self::process_message_received_at`] says what it costs.
    pub fn process_message(&mut self, group_id: &[u8], message: &[u8]) -> Result<Incoming> {
        self.process_message_received_at(group_id, message, 0)
    }

    /// [`Self::process_message`], for a message the delivery service received
    /// at `received_at`, Unix seconds (the mailbox envelope's `received_at`),
    /// or `0` when the caller does not know it.
    ///
    /// The time decides two things ([`crate::identity::judge_message_sender`]).
    /// A message from a device whose account signed its key out, which this
    /// device holds, is read only when it was received before the revocation
    /// took effect; an unknown time is treated as after, so the message is
    /// refused. And a message from a leaf whose credential has lapsed
    /// is refused as new when it was received at or after the
    /// credential's `exp`, this device's own wall standing in for an unknown
    /// time.
    pub fn process_message_received_at(
        &mut self,
        group_id: &[u8],
        message: &[u8],
        received_at: i64,
    ) -> Result<Incoming> {
        match Self::content_type_of(message)? {
            openmls::prelude::ContentType::Application => {
                self.process_application(group_id, message, None, received_at)
            }
            openmls::prelude::ContentType::Commit => Err(Error::WrongDoor(
                "a commit arrives only through the commit door",
            )),
            openmls::prelude::ContentType::Proposal => match self.process_any(group_id, message) {
                Ok(incoming) => Ok(incoming),
                Err(Error::Storage(err)) => Err(Error::Storage(err)),
                Err(err) => {
                    log::info!("peachy-mls: a proposal not taken on the message door: {err}");
                    Err(Error::WrongDoor(
                        "the one proposal taken on the message door is a leave this device can queue",
                    ))
                }
            },
        }
    }

    /// [`Self::process_message`] for the message inside mailbox envelope
    /// `envelope_id`, with what it opens to KEPT IN THE SAME WRITE THAT
    /// SPENDS ITS KEY, until the client releases it ([`Self::release_opened`])
    /// once its own copy is stored.
    ///
    /// A client stores what a message said after this call answers, and the
    /// key is spent by then: a process that dies between the two (or a store
    /// that refuses the client's write) would leave a message whose key is
    /// gone and whose words are nowhere, and the mailbox hands the envelope
    /// over again only to read as a duplicate. Here the same envelope handed
    /// over again, the same bytes in the same group, answers what it opened
    /// to the first time, so the client stores it then.
    ///
    /// An empty `envelope_id` keeps nothing, as [`Self::process_message`];
    /// so does anything that is not an application message from another
    /// device. A message refused because its keep could not be written spends
    /// nothing ([`Self::process_whole`]). A record is kept under the id AND
    /// the message's digest, so another message handed over under an id
    /// already holding one (a server reusing ids) is kept beside it, never
    /// over it; a record whose group differs is not answered, and the message
    /// goes through the door as any other. An id holding a NUL keeps nothing.
    pub fn process_message_as(
        &mut self,
        group_id: &[u8],
        message: &[u8],
        envelope_id: &str,
    ) -> Result<Incoming> {
        self.process_message_as_received_at(group_id, message, envelope_id, 0)
    }

    /// [`Self::process_message_as`], for a message the delivery service
    /// received at `received_at`, Unix seconds, or `0` when the caller does
    /// not know it ([`Self::process_message_received_at`] says what the time
    /// decides). A message answered from what was kept was judged when it
    /// was kept.
    pub fn process_message_as_received_at(
        &mut self,
        group_id: &[u8],
        message: &[u8],
        envelope_id: &str,
        received_at: i64,
    ) -> Result<Incoming> {
        if envelope_id.is_empty() || envelope_id.contains('\0') {
            return self.process_message_received_at(group_id, message, received_at);
        }
        let digest = crate::storage::opened_digest(message);
        if let Some(mut kept) = self
            .provider
            .peachy_storage()
            .opened_content(envelope_id, &digest)?
        {
            if kept.group_id == group_id && kept.digest == digest {
                // Judged when it was kept.
                return Ok(Incoming::Application {
                    sender: kept.sender,
                    // Moved out, not copied: the caller owns the words.
                    plaintext: std::mem::take(&mut *kept.plaintext),
                });
            }
        }
        match Self::content_type_of(message)? {
            openmls::prelude::ContentType::Application => {
                self.process_application(group_id, message, Some(envelope_id), received_at)
            }
            _ => self.process_message_received_at(group_id, message, received_at),
        }
    }

    /// The client's own copy of what envelope `envelope_id` opened to is
    /// stored: what [`Self::process_message_as`] kept of it goes. Answers
    /// whether anything was kept; with nothing kept, nothing is written. A
    /// client releases every envelope it acknowledges, whether or not this
    /// run opened it, so one kept by a run that died is let go once the
    /// client finds its copy. Every record under the id goes, whatever
    /// message it was kept for.
    ///
    /// ERASED, not only deleted ([`Self::flushed_and_erased`]): the words
    /// are plaintext a disappearing message's timer may already have taken
    /// out of the client's own store, and a delete alone leaves the page that
    /// held them in the database file until the next erase. A release that
    /// is due to sweep the old and the excess sweeps them in the same write.
    pub fn release_opened(&mut self, envelope_id: &str) -> Result<bool> {
        Ok(self.release_opened_all(&[envelope_id])? > 0)
    }

    /// [`Self::release_opened`] for every envelope in `envelope_ids` AT ONCE:
    /// one write and one erase for them all, so a page that acknowledges many
    /// envelopes ends one write, not one per envelope. Answers how many held
    /// a record; with none, nothing is written. An empty id, or one holding a
    /// NUL, is passed over.
    pub fn release_opened_all(&mut self, envelope_ids: &[&str]) -> Result<usize> {
        let mut held = Vec::with_capacity(envelope_ids.len());
        for &id in envelope_ids {
            if !id.is_empty()
                && !id.contains('\0')
                && self.provider.peachy_storage().holds_opened_content(id)?
            {
                held.push(id);
            }
        }
        if held.is_empty() {
            return Ok(0);
        }
        self.synced(|client| {
            let outcome = client.sweep_opened_if_due().and_then(|()| {
                let mut released = 0;
                for id in &held {
                    if client
                        .provider
                        .peachy_storage()
                        .release_opened_content(id)?
                    {
                        released += 1;
                    }
                }
                Ok(released)
            });
            client.flushed_and_erased(())?;
            outcome
        })
    }

    /// An application message, through the message door. A REPLAY, the very
    /// bytes of a message this device opened before (its record:
    /// `storage.rs` `NS_OPENED`), is refused with [`Error::Duplicate`] before
    /// the engine reads it: its key was spent the first time, and nothing in
    /// the copy is new.
    ///
    /// ALL OR NOTHING: a message that is refused, at any step, spends
    /// nothing ([`Self::process_whole`]). OpenMLS takes the key from the
    /// ratchet before it checks the tag, and saves the ratchet before it
    /// checks the signature; any member can derive every member's keys, so
    /// without this a member could seal a copy under another's key, with a
    /// tag that holds and a signature that does not, and burn the key the
    /// real message needs.
    ///
    /// The engine's own word for a spent key (OpenMLS's
    /// `SecretTreeError::SecretReuseError`, [`Self::process_inner`]) is a
    /// duplicate only when the record agrees. A key is spent only by a
    /// message that opened, and the record holds every message that did, so
    /// what the record does not vouch for is a message opened by a build
    /// that kept no record, or one older than the last
    /// [`crate::storage::OPENED_KEPT`] the group remembers: a loss, said as
    /// one, and its content hint asks for it again.
    fn process_application(
        &mut self,
        group_id: &[u8],
        message: &[u8],
        keep_as: Option<&str>,
        received_at: i64,
    ) -> Result<Incoming> {
        let digest = crate::storage::opened_digest(message);
        if self
            .provider
            .peachy_storage()
            .opened_before(group_id, &digest)?
        {
            return Err(Error::Duplicate("this device already opened that message"));
        }
        match self.process_whole(group_id, message, keep_as, received_at) {
            Err(Error::Duplicate(_))
                if !self
                    .provider
                    .peachy_storage()
                    .opened_before(group_id, &digest)? =>
            {
                Err(Error::Mls(
                    "the key this message needs was spent, and not by opening it on this device"
                        .to_owned(),
                ))
            }
            outcome => outcome,
        }
    }

    /// THE COMMIT DOOR: one incoming group message, for an entry the arbiter ordered
    /// (envelope kind [`crate::envelope::ENVELOPE_KIND_COMMIT`] in a
    /// `MAILBOX_KIND_COMMIT` entry). Only a commit goes through; anything else
    /// is refused with [`Error::WrongDoor`] before the engine reads it, so an application message wrapped as a
    /// commit neither spends a ratchet nor reads as a commit that strands.
    /// [`Client::process_message`] says why the two are kept apart.
    ///
    /// **A carried commit** ([`crate::carried_commit`]) brings the leave
    /// proposals it names: each is taken through the leave door first, as if
    /// it had arrived as a message (one this device already holds, or one the
    /// door refuses, changes nothing), and then the commit. Anything carried
    /// that is not a proposal is not opened.
    ///
    /// **A veto frame** ([`crate::steward`]) around the commit is stripped
    /// first, and the commit it wraps taken like any other; a veto that does
    /// not verify is logged and refuses nothing in this build.
    ///
    /// **The sealed stamp** handed in through [`Self::note_commit_stamp`] is
    /// checked against the verifier the commit really produces, and the
    /// result kept for [`Self::take_commit_check`]. It only alerts in this
    /// build: no commit is refused for its stamp.
    pub fn process_commit(&mut self, group_id: &[u8], message: &[u8]) -> Result<Incoming> {
        let stamp = self.pending_stamps.remove(group_id);
        self.synced(|client| client.process_commit_inner(group_id, message, stamp))
    }

    /// THE MAILBOX DOOR: one opened mailbox entry, routed by BOTH the kind
    /// the delivery service put on the entry (`mailbox_kind`,
    /// [`crate::envelope::MAILBOX_KIND_MLS`] or
    /// [`crate::envelope::MAILBOX_KIND_COMMIT`]) and the kind sealed inside
    /// it (`envelope_kind`, the [`crate::envelope::OpenedEnvelope::kind`]
    /// [`Self::open_envelope`] answered), never one of them alone
    /// ([`crate::envelope::envelope_door`]). A commit goes to
    /// [`Self::process_commit`] only from a COMMIT entry, and a message to
    /// [`Self::process_message_received_at`] only from an MLS entry;
    /// anything else, a commit that skipped the arbiter included, is refused
    /// with [`Error::WrongDoor`] before the engine reads it, so nothing moves.
    /// A seat ask and a call signal are not group messages, and are refused
    /// here too: their own readers take them.
    pub fn process_mailbox_entry(
        &mut self,
        group_id: &[u8],
        mailbox_kind: u32,
        envelope_kind: u8,
        inner: &[u8],
        received_at: i64,
    ) -> Result<Incoming> {
        use crate::envelope::{envelope_door, EnvelopeDoor};
        match envelope_door(mailbox_kind, envelope_kind) {
            EnvelopeDoor::Commit => self.process_commit(group_id, inner),
            EnvelopeDoor::Message => {
                self.process_message_received_at(group_id, inner, received_at)
            }
            EnvelopeDoor::SeatAsk | EnvelopeDoor::Call => Err(Error::WrongDoor(
                "a seat ask or a call signal is not a group message: take it through its own reader",
            )),
            EnvelopeDoor::Drop => Err(Error::WrongDoor(
                "this envelope kind does not belong in this kind of mailbox entry: a commit is \
                 taken only from a COMMIT entry, a message only from an MLS entry",
            )),
        }
    }

    fn process_commit_inner(
        &mut self,
        group_id: &[u8],
        message: &[u8],
        stamp: Option<Vec<u8>>,
    ) -> Result<Incoming> {
        let carried = crate::carried_commit::split_carried(message)?;
        let commit = carried.commit;
        match Self::content_type_of(commit)? {
            openmls::prelude::ContentType::Commit => {
                if let Some(signed) = carried.veto.filter(|_| self.honors_stewards) {
                    if self.veto_verdict(group_id, signed, carried.vetoed)?
                        == crate::steward::VetoVerdict::None
                    {
                        log::warn!(
                            "peachy-mls: a commit came in a veto frame the steward key does not \
                             verify; taken as a commit (this build refuses nothing for it)"
                        );
                    }
                }
                let before = match &stamp {
                    Some(_) => self.stamp_inputs(group_id),
                    None => None,
                };
                // The steward key the stamp names, when it opens under this
                // epoch's send key: recorded at the epoch the merge enters
                // (`note_copy_epoch`), inside the merge's own write, and what
                // decides whether this device counts the group as enrolled
                // ([`Self::enrolled_steward_key`]).
                for proposal in &carried.proposals {
                    self.take_carried_proposal(group_id, proposal)?;
                }
                if let (Some(sealed), Some(inputs)) = (stamp.as_deref(), before.as_ref()) {
                    if let Ok(opened) =
                        crate::steward::open_stamp(&inputs.send_key, inputs.epoch, sealed)
                    {
                        self.stamp_stewards
                            .insert(group_id.to_vec(), opened.steward_pub);
                    }
                }
                self.last_refusal_authenticated = false;
                let outcome = self.process_any(group_id, commit);
                let stamped = self.stamp_stewards.remove(group_id);
                self.steward_merges.remove(group_id);
                if outcome.is_err() {
                    // A REFUSED commit's stamp still counts: it opened under
                    // this epoch's send key, so it is the server's word about
                    // the handle's key whatever the commit was. So a copy
                    // whose first stamped commit is the one it cannot apply
                    // (seated by a Welcome just before it) is enrolled, and
                    // can hold. Kept only when it names the key the group
                    // counts here, so a refused rotation un-enrolls nothing.
                    if let Some(Some(key)) = stamped {
                        // A stamp that named a key is evidence a steward
                        // exists whatever the commit was; one that named none
                        // on a refused commit proves nothing either way.
                        if let Err(err) = self
                            .provider
                            .peachy_storage()
                            .note_stamp_opened(group_id, true)
                        {
                            log::warn!(
                                "peachy-mls: could not keep a refused commit's stamp: {err}"
                            );
                        }
                        self.keep_refused_stamp(group_id, &key);
                    }
                }
                self.note_commit_refusal(group_id, message, outcome.is_err());
                if let Ok(Incoming::Commit(merged)) = &outcome {
                    // THE MERGE IS ALREADY DURABLE (`process_any` commits it),
                    // so nothing below may write, or fail the door: a step
                    // failing here would answer an error for a commit this
                    // device has taken, and its retry would find it gone
                    // (tests/store_fault_rollback.rs). A hold needs no clearing:
                    // it holds only at the epoch it was entered at
                    // (`GroupHold::holds`), which this merge has left.
                    let check =
                        match self.check_stamp(group_id, message, stamp.as_deref(), before, merged)
                        {
                            Ok(check) => check,
                            Err(err) => {
                                log::warn!("peachy-mls: could not check a commit's stamp: {err}");
                                return outcome;
                            }
                        };
                    if check.alerts() {
                        log::warn!(
                            "peachy-mls: a commit's sealed stamp did not hold up ({:?}, mac {:?}, \
                             steward {:?}); this build only alerts",
                            check.stamp,
                            check.mac,
                            check.steward
                        );
                    }
                    self.commit_checks.insert(group_id.to_vec(), check);
                }
                outcome
            }
            openmls::prelude::ContentType::Application => Err(Error::WrongDoor(
                "an application message is not taken on the commit door",
            )),
            openmls::prelude::ContentType::Proposal => Err(Error::WrongDoor(
                "a proposal is not taken on the commit door",
            )),
        }
    }

    /// A group message's content type, off its framing and with no key.
    fn content_type_of(message: &[u8]) -> Result<openmls::prelude::ContentType> {
        let incoming = MlsMessageIn::tls_deserialize_exact(message)?;
        let protocol = incoming
            .try_into_protocol_message()
            .map_err(|_| Error::invalid("that message is not a group message"))?;
        Ok(protocol.content_type())
    }

    /// One proposal a carried commit brings, taken through the leave door
    /// exactly as [`Self::process_message`] takes one: queued when it is a
    /// leave this device can queue, and otherwise dropped, the commit then
    /// standing or falling on what this device holds. A proposal it already
    /// holds is refused by the engine as a replay, which is the ordinary case
    /// for every member the leave reached. Only a transient store failure is
    /// an error, so the entry is held and tried again.
    fn take_carried_proposal(&mut self, group_id: &[u8], proposal: &[u8]) -> Result<()> {
        if !matches!(
            Self::content_type_of(proposal),
            Ok(openmls::prelude::ContentType::Proposal)
        ) {
            log::info!("peachy-mls: a carried commit carried something other than a proposal");
            return Ok(());
        }
        match self.process_any(group_id, proposal) {
            Ok(_) => Ok(()),
            Err(Error::Storage(err)) => Err(Error::Storage(err)),
            Err(err) => {
                log::debug!("peachy-mls: a carried proposal not taken: {err}");
                Ok(())
            }
        }
    }

    /// Drop every trace of a group from this device.
    ///
    /// The other half of the rejoin, and the reason there is no `leave_stale`:
    /// a device that has fallen off the ratchet CANNOT ACT IN THE GROUP. It
    /// cannot sign a Remove of its own leaf that anyone will accept, because
    /// the signature would be over a group context from an epoch that no longer
    /// exists; it cannot even encrypt. Everything it can do is local, and this
    /// is that: forget, so that the Welcome a live member mints can create the
    /// group fresh rather than collide with the stale copy.
    ///
    /// The group state goes from storage too, not just from the open map. A
    /// half-forgotten group is the worst of both — invisible to the caller and
    /// still occupying the id a Welcome is about to want.
    ///
    /// Idempotent in spirit but not in signature: forgetting a group this
    /// client does not hold is [`Error::NoSuchGroup`], because the caller
    /// asking is a caller who believed it held one.
    ///
    /// **The roster is kept.** Forgetting is how a device that fell off a
    /// group's ratchet starts its rejoin: the people of its copy, each under
    /// the account key their leaves carried, are kept until a copy in the id
    /// is confirmed, less each person this device sees leave in the
    /// meantime, and a Welcome into the id is drawn against them: who was
    /// added, who is gone, whether the admins changed
    /// ([`RejoinReport`]). They refuse nobody. A copy that names nobody but
    /// this device's own person keeps that person, so a Welcome back is
    /// still drawn. Nothing is kept for a copy this device was removed from
    /// together with its person; an earlier kept roster then stands. A
    /// person who leaves on purpose drops it with
    /// [`Self::forget_remembered_roster`]. Rejoin reports not taken yet are
    /// kept too.
    ///
    /// **So is the epoch**, for good: a Welcome into the id at or below the
    /// epoch forgotten here is refused ([`Self::join_from_welcome`]).
    ///
    /// A group this device is LEAVING ([`Self::begin_leave`]) is forgotten
    /// too, and the leave given up with it.
    pub fn forget_group(&mut self, group_id: &[u8]) -> Result<()> {
        self.synced(|client| {
            if let Some(stub) = client.leaving.remove(group_id) {
                client.groups.insert(group_id.to_vec(), stub);
            }
            client.forget_group_now(group_id)
        })
    }

    fn forget_group_now(&mut self, group_id: &[u8]) -> Result<()> {
        if !self.groups.contains_key(group_id) {
            return Err(Error::NoSuchGroup);
        }
        self.refuse_unsettled(group_id)?;
        self.remember_held_copy(group_id)?;
        // The epoch goes on as the group's mark: a Welcome back must come
        // from later than this ([`Self::epoch_mark`]).
        self.raise_epoch_mark_to_held(group_id)?;
        let mut group = self.groups.remove(group_id).ok_or(Error::NoSuchGroup)?;
        let founding_only = group.epoch().as_u64() == 0;
        self.refused_commits.remove(group_id);
        self.recovery.forget_copy(group_id);
        self.pending_stamps.remove(group_id);
        self.commit_checks.remove(group_id);
        self.saved_stages.remove(group_id);
        self.provider
            .peachy_storage()
            .forget_staged_commit(group_id)?;
        group
            .delete(self.provider.storage())
            .map_err(|err| Error::Mls(format!("could not delete the group state: {err}")))?;
        // The index entry goes AFTER the state, so a crash between the two
        // leaves an id pointing at nothing — which `reopen_groups` cleans up —
        // rather than state nothing points at, which nothing would ever find.
        self.provider.peachy_storage().forget_group(group_id)?;
        self.provider
            .peachy_storage()
            .set_head_state(group_id, HeadState::Unrecorded)?;
        self.provider
            .peachy_storage()
            .forget_account_seen(group_id)?;
        self.provider
            .peachy_storage()
            .forget_leaf_rotation(group_id)?;
        self.provider
            .peachy_storage()
            .forget_welcome_sender(group_id)?;
        self.provider
            .peachy_storage()
            .forget_copy_records(group_id)?;
        self.provider
            .peachy_storage()
            .forget_carried_leaves(group_id)?;
        self.provider.peachy_storage().forget_leaving(group_id)?;
        // WHO ITS DEVICE KEYS BELONGED TO stays 30 days past the copy, so a
        // seal for this group still names its sender while this device holds
        // no copy ([`Self::next_reopenable`]).
        // A copy never past its founding (one given up for another member's
        // founding of the same id) held nobody but this device: it names
        // nobody, so it keeps nothing.
        let storage = self.provider.peachy_storage();
        if founding_only {
            storage.forget_leaf_people(group_id)?;
        } else if let Some(mut people) = storage.leaf_people(group_id)? {
            people.forgotten_at_ms = u64::try_from(self.identity_provider.now_unix_ms())
                .unwrap_or(0)
                .max(1);
            storage.set_leaf_people(group_id, &people)?;
        }
        self.reopen_anew();
        self.flushed_and_erased(())
    }

    /// Keep what the copy of `group_id` held now says of the group, before
    /// it is deleted ([`Self::forget_group`]) or replaced by a seat no head
    /// has confirmed ([`Self::take_seat`]), for the rejoin report
    /// ([`Self::judge_replacing_welcome`]).
    ///
    /// A copy that matched a head once, lapsed or not, keeps its people
    /// (each under the account key their leaves carry, this device's own
    /// person included) and its group state, the `peachy_group_meta` whose
    /// `adm` a Welcome back is drawn against: no head's answer decides
    /// whether a forget remembers them. The roster and state are kept
    /// together, or neither: an earlier kept pair stands for a copy this
    /// device was removed from with its person.
    ///
    /// A copy no head matched keeps only its roster: the people a Welcome
    /// that comes after it is reported against.
    fn remember_held_copy(&self, group_id: &[u8]) -> Result<()> {
        let Some(held) = self.groups.get(group_id) else {
            return Ok(());
        };
        // The people kept are seated now: a departed record of theirs (one
        // never cleared) must not exempt them later.
        self.clear_departed_of_seated(group_id)?;
        let storage = self.provider.peachy_storage();
        // Its devices, for the devices a Welcome back leaves out of people
        // it keeps ([`Self::dropped_devices`]), whether a head matched it or
        // not: they refuse nobody.
        let devices = self.devices_of_held(group_id);
        if !devices.is_empty() {
            storage.set_remembered_devices(group_id, &devices)?;
        }
        let Some(claim) = self.vouched_claim_of_held(group_id)? else {
            let claim = self.unvouched_held_roster(group_id)?;
            if !claim.is_empty() {
                storage.set_remembered_unvouched(group_id, &claim)?;
            }
            return Ok(());
        };
        if !claim.is_empty() {
            storage.set_remembered_roster(group_id, &claim)?;
            match group_meta_from_context(held.extensions()) {
                Some(meta) => storage.set_remembered_policy(group_id, &meta)?,
                None => storage.forget_remembered_policy(group_id)?,
            }
        }
        Ok(())
    }

    /// The actor id of the member whose commit seated this device in
    /// `group_id` by a Welcome: the Welcome's GroupInfo signer, read from the
    /// verified tree at the join and kept with the group's state (so it
    /// survives a restart and is the same answer in every process that opens
    /// this store). `None` for a group this device founded, one it joined on
    /// a build before this was kept, or one it does not hold (forgetting a
    /// group forgets this too). Read from storage, not the open groups, so a
    /// process whose open map has not caught up with a join another process
    /// made over the same store (a notification process, say) still
    /// answers.
    ///
    /// What a client asks it: was I added by one of MY OWN devices (a linked
    /// device being seated, which says nothing about whether this person wants
    /// to be in the group) or by somebody else (docs/account-store.md §Record
    /// values, **Leaving a group**).
    pub fn welcome_sender(&self, group_id: &[u8]) -> Result<Option<String>> {
        Ok(self.provider.peachy_storage().welcome_sender(group_id)?)
    }

    /// Who a seated leaf belongs to, with every credential check but the
    /// clock: kid, key use, signature and leaf binding still hold, and an
    /// expired credential still names its actor.
    fn seated_identity(&self, group_id: &[u8], leaf_index: u32) -> Option<PeachyIdentity> {
        let group = self.groups.get(group_id)?;
        let member = group.members().find(|m| m.index.u32() == leaf_index)?;
        self.identity_provider
            .validate_seated_credential(&member.credential, &member.signature_key, i64::MAX)
            .ok()
            .map(|(identity, _lapsed)| identity)
    }

    /// A device this account forgot as removed ([`Self::forget_own_device`]),
    /// by its id or by any key it was seen holding, is seated by no add of
    /// this device's, a founding's included, whatever the own-device check
    /// answers: forgetting is permanent and device ids are never
    /// reused, so no device the person means to seat is refused here. Fails
    /// closed, as [`Self::is_forgotten_own_device`] does.
    fn refuse_if_forgotten_own_device(&self, joining: &PeachyIdentity) -> Result<()> {
        if joining.actor_id == self.identity.actor_id
            && self.is_forgotten_own_device(&joining.device_id, &joining.device_key)
        {
            return Err(Error::invalid("that device was removed from this account"));
        }
        Ok(())
    }

    /// ONE DEVICE, ONE LEAF. Refuse to seat `joining` while a leaf of the
    /// group other than `except` (the leaf a replace takes back) already
    /// carries its device id, under any key. A device id names one install;
    /// a second leaf under it is either a duplicate the caller failed to
    /// skip or another device wearing that install's name, and a device
    /// that finds its own id under a key it does not hold must never be the
    /// only one able to tell (`own_devices.rs` §A leaf this device did not
    /// see vouched for). Read with every credential check but the clock, as
    /// [`Self::seated_identity`] reads one: a lapsed leaf still holds its
    /// seat until it is removed.
    fn refuse_if_device_seated(
        &self,
        group_id: &[u8],
        joining: &PeachyIdentity,
        except: Option<u32>,
    ) -> Result<()> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        let seated = group.members().any(|member| {
            Some(member.index.u32()) != except
                && self
                    .identity_provider
                    .validate_seated_credential(&member.credential, &member.signature_key, i64::MAX)
                    .is_ok_and(|(identity, _)| identity.device_id == joining.device_id)
        });
        if seated {
            return Err(Error::invalid(
                "that device already holds a leaf in this group; a device comes back by a replace of its own leaf",
            ));
        }
        Ok(())
    }

    /// The leaf index of a device id in this group, if it is there.
    pub fn leaf_of_device(&self, group_id: &[u8], device_id: &str) -> Result<u32> {
        crate::credential::require_valid_id(device_id, "a device_id")?;
        self.roster(group_id)?
            .into_iter()
            .find(|entry| {
                entry
                    .identity
                    .as_ref()
                    .is_ok_and(|id| id.device_id == device_id)
            })
            .map(|entry| entry.leaf_index)
            .ok_or(Error::NoSuchMember)
    }

    /// Rotate this device's leaf key and commit it.
    ///
    /// The post-compromise-security half of MLS: after a self-update, an
    /// attacker who had this device's old leaf secrets can no longer read the
    /// group. The scheduled rotation does not come through here but through
    /// [`Self::refresh_credential`], which clients run before a send and in
    /// their foreground pass ([`Self::leaf_rotation_due`]); this stays the
    /// explicit door.
    pub fn self_update(&mut self, group_id: &[u8]) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome = client.self_update_inner(group_id, true);
            client.stage_committed(group_id, outcome)
        })
    }

    /// [`Self::self_update`] with the policy and lapsed-leaf checks OFF. Test-only, for the same reason as
    /// [`Self::forge_remove_member`].
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_self_update(&mut self, group_id: &[u8]) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome = client.self_update_inner(group_id, false);
            client.stage_committed(group_id, outcome)
        })
    }

    /// Overwrite a group's STORED wire format policy with another a store can
    /// hold: `MIXED_PLAINTEXT_WIRE_FORMAT_POLICY` (plaintext handshakes out,
    /// either framing in), the first builds' policy, or
    /// `MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY` (sealed out, either framing in),
    /// the transitional one between those and today's.
    ///
    /// Two jobs, both test-only. It is the only way to test the upgrade at open,
    /// because no honest path produces the state it repairs any more — it writes
    /// exactly what that build wrote plus the rest of today's join config, so a
    /// test can drop the client, open it again and assert what the group now
    /// sends and accepts. And, held in memory without a reopen, it is the only
    /// way to make a member frame a handshake in the clear at all, which is what
    /// proves the other members refuse one. See `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_stored_wire_format_policy(
        &mut self,
        group_id: &[u8],
        policy: WireFormatPolicy,
    ) -> Result<()> {
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(policy)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(RETAINED_PAST_EPOCHS)
            .sender_ratchet_configuration(sender_ratchet())
            .padding_size(APPLICATION_PADDING_BLOCK)
            .build();
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        group
            .set_configuration(self.provider.storage(), &config)
            .map_err(|err| Error::Mls(format!("could not rewrite the wire format: {err}")))?;
        self.flushed(())
    }

    /// Rewrite this device's STORED sender-ratchet window for a group to
    /// `tolerance`, as a build from before [`OUT_OF_ORDER_TOLERANCE`] stored
    /// it (OpenMLS's default is 5), so a test can drop the client, reopen it
    /// and assert the open-time upgrade widened it. See `test-forgery` in
    /// Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_stored_out_of_order_tolerance(
        &mut self,
        group_id: &[u8],
        tolerance: u32,
    ) -> Result<()> {
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PEACHY_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(RETAINED_PAST_EPOCHS)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                tolerance,
                MAXIMUM_FORWARD_DISTANCE,
            ))
            .padding_size(APPLICATION_PADDING_BLOCK)
            .build();
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        group
            .set_configuration(self.provider.storage(), &config)
            .map_err(|err| Error::Mls(format!("could not rewrite the sender ratchet: {err}")))?;
        self.flushed(())
    }

    /// Rewrite this device's STORED past-epoch bound for a group to `epochs`,
    /// as a build from before [`RETAINED_PAST_EPOCHS`] was lowered stored it
    /// (32), so a test can fill the wider store, drop the client, reopen it
    /// and assert the open cut it down. See `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_stored_past_epochs(&mut self, group_id: &[u8], epochs: usize) -> Result<()> {
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PEACHY_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(epochs)
            .sender_ratchet_configuration(sender_ratchet())
            .padding_size(APPLICATION_PADDING_BLOCK)
            .build();
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        group
            .set_configuration(self.provider.storage(), &config)
            .map_err(|err| Error::Mls(format!("could not rewrite the past-epoch bound: {err}")))?;
        self.flushed(())
    }

    /// A standalone by-reference Update proposal for this device's own leaf,
    /// which no Peachy client ever sends — so a test can hand one to every
    /// other member and prove they all reach the same verdict on it. The
    /// proposal also sits in this client's own store. Test-only; see
    /// `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_propose_self_update(&mut self, group_id: &[u8]) -> Result<Vec<u8>> {
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        let (message, _reference) = group
            .propose_self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .map_err(mls_err)?;
        // A proposal is a write (the proposal store, the handshake ratchet),
        // committed before the call returns like any other.
        let bytes = message.to_bytes().map_err(mls_err)?;
        self.flushed(bytes)
    }

    /// A standalone by-reference Remove proposal, as a modified client would
    /// send one, so a test can prove every member refuses it and that it
    /// never rides into somebody else's commit. Test-only; see `test-forgery`
    /// in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_propose_remove(&mut self, group_id: &[u8], leaf_index: u32) -> Result<Vec<u8>> {
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        let (message, _reference) = group
            .propose_remove_member(&self.provider, &self.signer, LeafNodeIndex::new(leaf_index))
            .map_err(mls_err)?;
        // A proposal is a write (the proposal store, the handshake ratchet),
        // committed before the call returns like any other.
        let bytes = message.to_bytes().map_err(mls_err)?;
        self.flushed(bytes)
    }

    /// A standalone by-reference proposal setting the group's meta to
    /// `value`, as a modified client would send one. Test-only; see
    /// [`Self::forge_propose_remove`].
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_propose_group_meta(&mut self, group_id: &[u8], value: &[u8]) -> Result<Vec<u8>> {
        let extensions = {
            let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
            group_context_extensions_with_meta(group.extensions(), value)?
        };
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        let (message, _reference) = group
            .propose_group_context_extensions(&self.provider, extensions, &self.signer)
            .map_err(mls_err)?;
        // A proposal is a write (the proposal store, the handshake ratchet),
        // committed before the call returns like any other.
        let bytes = message.to_bytes().map_err(mls_err)?;
        self.flushed(bytes)
    }

    /// The engine behind both doors, with no door: a test reaches the checks
    /// that stand behind them, such as the refusal of a standalone proposal,
    /// which both doors turn away before the engine reads it. Test-only; see
    /// `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_process_any(&mut self, group_id: &[u8], message: &[u8]) -> Result<Incoming> {
        self.process_any(group_id, message)
    }

    /// Drop this device's record of the application messages it opened in
    /// `group_id`, as a build that kept none would have left it. Test-only;
    /// see `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_forget_opened(&mut self, group_id: &[u8]) -> Result<()> {
        self.provider.peachy_storage().forget_opened(group_id)?;
        self.flushed(())
    }

    /// Seal `plaintext` as an application message under this device's next
    /// sending key, with a signature from a key that is not its leaf's, and
    /// leave the ratchet as it was, so the real message this device sends
    /// next uses that same key. What a member sends who derived another's
    /// key from the group's secret tree, which any member can: a copy whose
    /// tag holds and whose signature does not. Test-only; see
    /// `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_badly_signed_application(
        &mut self,
        group_id: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let wrong = SignatureKeyPair::new(SignatureScheme::ED25519)
            .map_err(|err| Error::Mls(format!("could not make a signature key: {err}")))?;
        self.synced(|client| {
            let group = client.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            group.set_aad(crate::hint::hint_aad_with_commitment(
                crate::hint::CONTENT_HINT_DEFAULT,
                None,
            ));
            let bytes = group
                .create_message(&client.provider, &wrong, plaintext)
                .map_err(mls_err)
                .and_then(|created| created.to_bytes().map_err(mls_err));
            client.undo_message(group_id);
            bytes
        })
    }

    /// Put a received standalone proposal in this device's proposal store
    /// with none of the checks the engine runs on receipt: the store a build from
    /// before proposals by reference were refused may still hold. Test-only;
    /// see `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_store_proposal(&mut self, group_id: &[u8], message: &[u8]) -> Result<()> {
        let protocol = MlsMessageIn::tls_deserialize_exact(message)?
            .try_into_protocol_message()
            .map_err(|_| Error::invalid("that message is not a group message"))?;
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        let processed = group
            .process_message(&self.provider, protocol)
            .map_err(mls_err)?;
        let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content() else {
            return Err(Error::invalid("that message is not a standalone proposal"));
        };
        group
            .store_pending_proposal(self.provider.storage(), *queued)
            .map_err(|err| Error::Mls(err.to_string()))?;
        self.flushed(())
    }

    /// An Add that sweeps in this device's whole proposal store and runs none
    /// of the committer's checks: the commit a build that still consumed the
    /// store would have sent. Test-only; see `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_add_member_sweeping(
        &mut self,
        group_id: &[u8],
        key_package: &[u8],
    ) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome = client.stage_add_member_sweeping(group_id, key_package);
            client.stage_committed(group_id, outcome)
        })
    }

    #[cfg(feature = "test-forgery")]
    fn stage_add_member_sweeping(
        &mut self,
        group_id: &[u8],
        key_package: &[u8],
    ) -> Result<CommitBundle> {
        let MlsMessageBodyIn::KeyPackage(incoming) =
            MlsMessageIn::tls_deserialize_exact(key_package)?.extract()
        else {
            return Err(Error::invalid("that message is not a KeyPackage"));
        };
        let key_package = incoming
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls_err)?;
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        let (commit, welcome, _group_info) = group
            .add_members(&self.provider, &self.signer, &[key_package])
            .map_err(mls_err)?;
        Ok(CommitBundle {
            commit: commit.to_bytes().map_err(mls_err)?,
            welcome: Some(crate::welcome_frame::frame_welcome(
                &welcome.to_bytes().map_err(mls_err)?,
                0,
            )?),
            epoch: group.epoch().as_u64() + 1,
        })
    }

    /// Remove the leaves at `removals` and add `key_packages`, in one commit,
    /// with none of the committer's checks: no policy, no account-key rule, no
    /// same-device rule for a reseat. What a modified member's client could
    /// send, so a test can prove every honest member refuses it. Staged, not
    /// merged. Test-only; see `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_commit(
        &mut self,
        group_id: &[u8],
        removals: &[u32],
        key_packages: &[&[u8]],
    ) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome = client.stage_forged_commit(group_id, removals, key_packages);
            client.stage_committed(group_id, outcome)
        })
    }

    #[cfg(feature = "test-forgery")]
    fn stage_forged_commit(
        &mut self,
        group_id: &[u8],
        removals: &[u32],
        key_packages: &[&[u8]],
    ) -> Result<CommitBundle> {
        let mut packages = Vec::with_capacity(key_packages.len());
        for bytes in key_packages {
            let MlsMessageBodyIn::KeyPackage(incoming) =
                MlsMessageIn::tls_deserialize_exact(bytes)?.extract()
            else {
                return Err(Error::invalid("that message is not a KeyPackage"));
            };
            packages.push(
                incoming
                    .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(mls_err)?,
            );
        }
        let plan = CommitPlan {
            removes: removals.to_vec(),
            adds: packages.len(),
            proposals_len: removals.len() * CommitPlan::inline_proposal(4)
                + packages
                    .iter()
                    .map(|package| CommitPlan::inline_proposal(package.tls_serialized_len()))
                    .sum::<usize>(),
            ..CommitPlan::default()
        };
        let bundle = self.padded_commit(group_id, &plan, |this| {
            let provider = &this.provider;
            let signer = &this.signer;
            let group = this.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            group
                .commit_builder()
                .consume_proposal_store(false)
                .propose_removals(removals.iter().map(|index| LeafNodeIndex::new(*index)))
                .propose_adds(packages)
                .force_self_update(true)
                .load_psks(provider.storage())
                .map_err(mls_err)?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(mls_err)?
                .stage_commit(provider)
                .map_err(mls_err)
        })?;
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        let commit = bundle.commit().to_bytes().map_err(mls_err)?;
        // A Welcome only ever travels in a frame (crate::welcome_frame).
        let welcome = match bundle.to_welcome_msg() {
            Some(message) => Some(crate::welcome_frame::frame_welcome(
                &message.to_bytes().map_err(mls_err)?,
                0,
            )?),
            None => None,
        };
        Ok(CommitBundle {
            commit,
            welcome,
            epoch: group.epoch().as_u64() + 1,
        })
    }

    /// Every proposal in this device's store by reference, plus inline
    /// Removes of `removals`, in one commit, with none of the committer's
    /// checks: a leave folded into another member's removal, as a modified
    /// client could send it. Staged, not merged. Test-only; see
    /// `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_commit_with_queued(
        &mut self,
        group_id: &[u8],
        removals: &[u32],
    ) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome = client.stage_forged_commit_with_queued(group_id, removals);
            client.stage_committed(group_id, outcome)
        })
    }

    #[cfg(feature = "test-forgery")]
    fn stage_forged_commit_with_queued(
        &mut self,
        group_id: &[u8],
        removals: &[u32],
    ) -> Result<CommitBundle> {
        let queued: Vec<u32> = self
            .groups
            .get(group_id)
            .ok_or(Error::NoSuchGroup)?
            .pending_proposals()
            .filter_map(|queued| match queued.proposal() {
                openmls::prelude::Proposal::Remove(remove) => Some(remove.removed().u32()),
                _ => None,
            })
            .collect();
        let plan = CommitPlan {
            removes: removals.iter().chain(&queued).copied().collect(),
            proposals_len: removals.len() * CommitPlan::inline_proposal(4)
                + queued.len() * CommitPlan::proposal_by_reference(),
            ..CommitPlan::default()
        };
        let bundle = self.padded_commit(group_id, &plan, |this| {
            let provider = &this.provider;
            let signer = &this.signer;
            let group = this.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            group
                .commit_builder()
                .consume_proposal_store(true)
                .propose_removals(removals.iter().map(|index| LeafNodeIndex::new(*index)))
                .load_psks(provider.storage())
                .map_err(mls_err)?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(mls_err)?
                .stage_commit(provider)
                .map_err(mls_err)
        })?;
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        Ok(CommitBundle {
            commit: bundle.commit().to_bytes().map_err(mls_err)?,
            welcome: None,
            epoch: group.epoch().as_u64() + 1,
        })
    }

    fn self_update_inner(&mut self, group_id: &[u8], honest: bool) -> Result<CommitBundle> {
        if honest {
            self.rules
                .evaluate(&self.own_context(ProposalKind::Update))
                .into_result()?;
        }
        if !self
            .groups
            .get(group_id)
            .ok_or(Error::NoSuchGroup)?
            .is_active()
        {
            return Err(Error::NotAMember);
        }
        // A plain rotation keeps the leaf's credential, so from a lapsed leaf
        // it renews nothing: refused here, and the move is refresh_credential.
        if honest {
            self.refuse_if_own_leaf_lapsed(group_id)?;
        }
        // A rotation carries today's capabilities too, for the renewal's
        // reason.
        let capabilities = self.leaf_capabilities();
        let plan = {
            let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
            let credential_len = group
                .own_leaf_node()
                .map(|leaf| leaf.credential().tls_serialized_len())
                .unwrap_or(0);
            CommitPlan {
                own_leaf_growth: own_leaf_growth(
                    group,
                    credential_len,
                    capabilities.tls_serialized_len(),
                ),
                ..CommitPlan::default()
            }
        };
        let parameters = LeafNodeParameters::builder()
            .with_capabilities(capabilities)
            .build();
        self.refuse_if_commit_staged(group_id)?;
        // A rotation and nothing else: nothing queued rides along (see
        // `add_member`).
        let bundle = self.padded_commit(group_id, &plan, |this| {
            let provider = &this.provider;
            let signer = &this.signer;
            let group = this.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            group
                .commit_builder()
                .consume_proposal_store(false)
                .force_self_update(true)
                .leaf_node_parameters(parameters)
                .load_psks(provider.storage())
                .map_err(mls_err)?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(mls_err)?
                .stage_commit(provider)
                .map_err(mls_err)
        })?;
        if honest {
            // Judged the way every receiver will judge it.
            self.refuse_own_commit_receivers_would_refuse(group_id)?;
        }
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        let commit = bundle.commit().to_bytes().map_err(mls_err)?;
        // STAGED, NOT MERGED. See §The commit lifecycle.
        Ok(CommitBundle {
            commit,
            welcome: None,
            epoch: group.epoch().as_u64() + 1,
        })
    }

    // ---- Refreshing this device's leaf credential ---------------------------
    //
    // A leaf's credential is the `pdc1` its device held when the leaf was made
    // — the one in the key package it was added by, or the creator's at
    // `create_group` — and it expires thirty days after the server minted it.
    // Every receiver checks the SENDER's leaf credential on every message it
    // processes, so a leaf nobody renews goes mute on the day it expires, in
    // every group at once. `RegisterDevice` hands the device a fresh credential
    // on every launch; this is how the fresh credential reaches a leaf that is
    // already seated: an ordinary MLS self-update whose new leaf carries it
    // (docs/identity.md §Refreshing a seated leaf).

    /// Hand this client a newer credential for the SAME device, in place.
    ///
    /// For a process that outlives a day — a browser tab left open, a Mac app
    /// that is never quit — and got a fresh `pdc1` from `RegisterDevice`
    /// without rebuilding the client. The credential must be for this client's
    /// actor, device and signing key, of the same kind, currently valid, and
    /// no older than the one it replaces; anything else is refused and the
    /// client keeps the credential it had.
    ///
    /// Touches no group. The next [`Self::refresh_credential`] is what carries
    /// it into one.
    ///
    /// `own_account_identity` names the account identity key this device
    /// derives from the account key it holds
    /// ([`ClientConfig::own_account_identity`]), every call: the key read
    /// where the host keeps it, or the one that has just arrived (an
    /// approval, a first mint, a start over). `None` keeps the key the
    /// client already holds, if any, and is for a device that holds none
    /// yet.
    ///
    /// A credential certified under any other key, or certified at all while
    /// the device names and holds no key, is refused as
    /// [`CredentialRejection::NotOwnAccountKey`], and the client keeps both the
    /// credential and the key it had.
    pub fn update_credential(
        &mut self,
        token: &[u8],
        own_account_identity: Option<[u8; ED25519_PUBLIC_KEY_BYTES]>,
    ) -> Result<()> {
        let own_account_identity = own_account_identity.or(self.own_account_identity);
        let public = self.signer.public().to_vec();
        let fresh = self.identity_provider.validate_token(token, &public)?;
        crate::identity::check_own_account_key(&fresh, own_account_identity.as_ref())?;
        if !Self::same_seat(&self.identity, &fresh) {
            return Err(Error::PolicyRefused(DenyReason::UpdateOfAnotherLeaf));
        }
        // A device's account certificate arrives once and then never
        // changes: anything else is a different account's claim on this
        // seat.
        if self.identity.account_key.is_some() && fresh.account_key != self.identity.account_key {
            return Err(Error::PolicyRefused(DenyReason::UpdateOfAnotherLeaf));
        }
        if fresh.expires_at < self.identity.expires_at {
            return Err(Error::invalid(
                "that credential expires before the one this client already holds",
            ));
        }
        self.credential_with_key = CredentialWithKey {
            credential: Credential::from(BasicCredential::new(token.to_vec())),
            signature_key: public.into(),
        };
        self.identity = fresh;
        self.own_account_identity = own_account_identity;
        Ok(())
    }

    /// The account identity key this client holds
    /// ([`ClientConfig::own_account_identity`], or the one
    /// [`Self::update_credential`] last installed); `None` while it holds none.
    pub(crate) fn held_account_identity(&self) -> Option<[u8; ED25519_PUBLIC_KEY_BYTES]> {
        self.own_account_identity
    }

    /// When the credential on this device's OWN leaf in `group_id` expires,
    /// in Unix seconds. Not the client's credential: the leaf's, which is the
    /// one every other member checks.
    ///
    /// Read out of the group's tree with no clock check, so a lapsed leaf
    /// answers with its past `exp` rather than an error — that is the case a
    /// caller most wants to see.
    pub fn own_leaf_credential_expires_at(&self, group_id: &[u8]) -> Result<i64> {
        Ok(self.own_leaf_credential(group_id)?.payload().exp)
    }

    /// Whether this device should commit [`Self::refresh_credential`] in
    /// `group_id` now.
    ///
    /// True when all of these hold, and the rule lives here rather than in
    /// four clients so that four clients cannot disagree about it:
    ///
    /// - the group is open and this device is still an active member of it;
    /// - its leaf's credential expires within
    ///   [`CREDENTIAL_REFRESH_WINDOW_SECONDS`](crate::identity::CREDENTIAL_REFRESH_WINDOW_SECONDS),
    ///   or already has;
    /// - and this client holds a credential that expires LATER than the
    ///   leaf's, so the commit would actually move something. A client opened
    ///   offline on yesterday's credential answers false rather than spending
    ///   an epoch to stand still.
    ///
    /// A group with a staged commit awaiting its verdict answers false too:
    /// OpenMLS builds one commit at a time, and the refresh can wait for the
    /// next open.
    pub fn credential_refresh_due(&self, group_id: &[u8]) -> Result<bool> {
        if !self.leaf_credential_expiring(group_id)? {
            return Ok(false);
        }
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if group.pending_commit().is_some() {
            return Ok(false);
        }
        if self.leaf_credential_past_grace(group_id)? {
            return Ok(false);
        }
        let leaf_exp = self.own_leaf_credential(group_id)?.payload().exp;
        let now = self.identity_provider.now_unix();
        // The capability renewal carries the credential the leaf already has
        // (or a fresher one), which every receiver accepts: the monotonic rule
        // in `check_renewed_leaf` allows an equal `exp`.
        // A rotation, like a capability renewal, may carry the credential the
        // leaf already has. So may the renewal that carries the tree clock
        // past a lapsed leaf's `exp` ([`Self::lapsed_leaf_awaits_tree_clock`]).
        if self.leaf_capabilities_stale(group_id)?
            || self.leaf_rotation_due(group_id)?
            || self.lapsed_leaf_awaits_tree_clock(group_id)?
        {
            return Ok(self.identity.expires_at >= leaf_exp && self.identity.expires_at > now);
        }
        Ok(self.identity.expires_at > leaf_exp && self.identity.expires_at > now)
    }

    /// Whether this device's own leaf in `group_id` lapsed longer ago than
    /// [`EXPIRED_LEAF_GRACE_SECONDS`](crate::identity::EXPIRED_LEAF_GRACE_SECONDS)
    /// — past the point where any member accepts anything from it, a renewal
    /// included.
    ///
    /// **The one state in which this device must stop talking in the group.**
    /// Everything it sends is refused by every current receiver, and a renewal
    /// is the dangerous case: the delivery service does not read credentials,
    /// so it would ACCEPT the commit, this device would merge it, and every
    /// other member would refuse it — a fork nothing repairs. So
    /// [`Self::refresh_credential`] refuses here and
    /// [`Self::credential_refresh_due`] answers false, and a client that sees
    /// true should stop claiming the conversation is sealed and ask for a seat
    /// instead (`RequestGroupRejoin`): another member's reconcile reads this
    /// leaf as unidentified, evicts it, and seats the device's fresh key
    /// package. docs/identity.md §Refreshing a seated leaf.
    ///
    /// **True a day EARLY**, at the grace minus
    /// [`RENEWAL_CUTOFF_MARGIN_SECONDS`](crate::identity::RENEWAL_CUTOFF_MARGIN_SECONDS):
    /// a renewal built in the last second of the grace is refused by any
    /// receiver whose clock is a little ahead or who processes it a little
    /// later, while the rest take it. Between the two lines the device stops
    /// renewing and asks for a seat, while every member still reads its leaf
    /// as identified — and the replace that answers the ask works on a lapsed
    /// leaf either way.
    ///
    /// False for a group this device is not active in.
    pub fn leaf_credential_past_grace(&self, group_id: &[u8]) -> Result<bool> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if !group.is_active() {
            return Ok(false);
        }
        let leaf_exp = self.own_leaf_credential(group_id)?.payload().exp;
        // The latest of this device's wall, the group's tree clock (as in
        // `refuse_if_own_leaf_lapsed`) and the `iat` of
        // the credential this device now HOLDS. Every receiver judges a
        // renewal's grace on the tree clock the renewal leaves behind, and the
        // renewal's own leaf is in it: a device whose wall
        // runs slow in a group nobody else has touched read false here, built
        // a renewal every receiver would refuse, had it refused by its own
        // check, and never asked for a seat.
        let now = self
            .identity_provider
            .now_unix()
            .max(Self::tree_clock(group, None))
            .max(self.identity.issued_at);
        Ok(now
            >= leaf_exp
                .saturating_add(crate::identity::EXPIRED_LEAF_GRACE_SECONDS)
                .saturating_sub(crate::identity::RENEWAL_CUTOFF_MARGIN_SECONDS))
    }

    /// Whether this device's own leaf in `group_id` is inside the refresh
    /// window, WHATEVER credential this client holds: an active person's leaf
    /// whose credential expires within
    /// [`CREDENTIAL_REFRESH_WINDOW_SECONDS`](crate::identity::CREDENTIAL_REFRESH_WINDOW_SECONDS),
    /// or already has.
    ///
    /// The question a client asks BEFORE [`Self::credential_refresh_due`]:
    /// when this is true and that is false, the client is holding nothing
    /// fresher than its leaf — a process that has been open for weeks, a Mac
    /// app nobody quits — and the move is to fetch today's credential from
    /// `RegisterDevice`, hand it over through [`Self::update_credential`], and
    /// ask again.
    pub fn leaf_credential_expiring(&self, group_id: &[u8]) -> Result<bool> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if !group.is_active() {
            return Ok(false);
        }
        // A leaf missing a capability this build requires is due a renewal
        // however far off its `exp` is: it blocks every member from renaming
        // the group ([`Self::leaf_capabilities_stale`]), and the renewal is
        // the one commit that carries today's capabilities into a seated leaf.
        if self.leaf_capabilities_stale(group_id)? {
            return Ok(true);
        }
        // So is a leaf due its periodic rotation ([`Self::leaf_rotation_due`]):
        // the renewal every client already runs before a send and in its
        // foreground pass (never on opening a conversation) IS an empty-path
        // self-update, so answering true here is what schedules
        // the rotation on every client with no client change — the same
        // road the capability upgrade above takes.
        if self.leaf_rotation_due(group_id)? {
            return Ok(true);
        }
        // And so is a renewal that would carry the tree clock past another
        // leaf's `exp`, after which that leaf's new messages are new however
        // the delivery service dates them
        // ([`Self::lapsed_leaf_awaits_tree_clock`]).
        if self.lapsed_leaf_awaits_tree_clock(group_id)? {
            return Ok(true);
        }
        let leaf_exp = self.own_leaf_credential(group_id)?.payload().exp;
        let now = self.identity_provider.now_unix();
        Ok(leaf_exp.saturating_sub(now) < crate::identity::CREDENTIAL_REFRESH_WINDOW_SECONDS)
    }

    /// Whether some other leaf in `group_id` has lapsed by the `iat` of the
    /// credential this device HOLDS, but not yet on the group's tree clock:
    /// a renewal carrying that credential would move the tree clock past the
    /// leaf's `exp`, and from that epoch on every member judges the leaf's
    /// messages sealed there new, whatever receive time the delivery service
    /// gives them ([`crate::identity::judge_message_sender`]). Read off the
    /// issuer's signed `iat` and `exp` alone, so it asks the delivery service
    /// for nothing; at most one renewal per lapsed leaf, since once the tree
    /// clock is past its `exp` the answer is false.
    /// docs/identity.md §A lapsed leaf's new messages.
    ///
    /// False for a group this device is not active in, and while a commit of
    /// this device's is staged.
    fn lapsed_leaf_awaits_tree_clock(&self, group_id: &[u8]) -> Result<bool> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if !group.is_active() || group.pending_commit().is_some() {
            return Ok(false);
        }
        let held_iat = self.identity.issued_at;
        let tree_clock = Self::tree_clock(group, None);
        if held_iat <= tree_clock {
            return Ok(false);
        }
        let own = group.own_leaf_index();
        Ok(group.members().any(|member| {
            member.index != own
                && PeachyIdentityProvider::claimed_expires_at(&member.credential)
                    .is_some_and(|exp| exp > tree_clock && exp <= held_iat)
        }))
    }

    /// Whether this device's own leaf in `group_id` is due its periodic
    /// rotation, for post-compromise security: it was put in the tree
    /// [`LEAF_ROTATION_INTERVAL_SECONDS`] ago or more, or this device has
    /// sealed [`LEAF_ROTATION_FRAME_BUDGET`] frames on it, or — in a group
    /// that seats exactly two people — it is
    /// [`ROUND_TRIP_ROTATION_MIN_SECONDS`] old or more and this device has
    /// opened an application message from the other person since.
    ///
    /// "Put in the tree" is the later of this device's own record — written
    /// when it created the group, joined it from a Welcome, or merged a commit
    /// of its own that carried an update path — and the `iat` of the credential
    /// the leaf carries, which is also the whole answer for a group with no
    /// record.
    ///
    /// Answered through [`Self::leaf_credential_expiring`] and
    /// [`Self::credential_refresh_due`], and carried out by
    /// [`Self::refresh_credential`]: a renewal commit is a forced self-update
    /// with no proposals, so it rotates the leaf's HPKE key whether or not the
    /// credential it carries is new. docs/mls-core.md §Periodic leaf rotation.
    ///
    /// False for a group this device is not active in, and while a commit of
    /// this device's is staged.
    pub fn leaf_rotation_due(&self, group_id: &[u8]) -> Result<bool> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if !group.is_active() || group.pending_commit().is_some() {
            return Ok(false);
        }
        let issued = self.own_leaf_issued_at(group_id)?;
        let (at, sent) = self
            .provider
            .peachy_storage()
            .leaf_rotation(group_id)?
            .unwrap_or((issued, 0));
        let at = at.max(issued);
        let now = self.identity_provider.now_unix();
        let age = now.saturating_sub(at);
        if age >= LEAF_ROTATION_INTERVAL_SECONDS || sent >= LEAF_ROTATION_FRAME_BUDGET {
            return Ok(true);
        }
        // The round trip ([`ROUND_TRIP_ROTATION_MIN_SECONDS`]): asked last,
        // because it is the one question that reads the tree.
        Ok(age >= ROUND_TRIP_ROTATION_MIN_SECONDS
            && self.provider.peachy_storage().peer_heard(group_id)?
            && Self::seats_one_other_person(group, &self.identity.actor_id))
    }

    /// Whether `group`'s tree seats exactly two people: this device's own
    /// and one other, however many devices each has. Read off the leaves'
    /// credentials without verifying them again, for the reason
    /// [`PeachyIdentityProvider::claimed_person`] gives; a leaf whose
    /// credential does not parse answers false, which leaves the group on
    /// the slower schedule.
    fn seats_one_other_person(group: &MlsGroup, own_actor: &str) -> bool {
        let mut other: Option<String> = None;
        for member in group.members() {
            let Some((actor, _, _)) = PeachyIdentityProvider::claimed_person(&member.credential)
            else {
                return false;
            };
            if actor == own_actor {
                continue;
            }
            match &other {
                None => other = Some(actor),
                Some(seen) if *seen == actor => {}
                Some(_) => return false,
            }
        }
        other.is_some()
    }

    /// The `iat` of the credential on this device's own leaf in `group_id`.
    fn own_leaf_issued_at(&self, group_id: &[u8]) -> Result<i64> {
        Ok(self.own_leaf_credential(group_id)?.payload().iat)
    }

    /// Record that this device's own leaf in `group_id` is new as of now.
    fn note_fresh_leaf(&self, group_id: &[u8]) -> Result<()> {
        let now = self.identity_provider.now_unix();
        self.provider
            .peachy_storage()
            .set_leaf_rotation(group_id, now, 0)?;
        self.provider.peachy_storage().clear_peer_heard(group_id)?;
        Ok(())
    }

    /// Commit a self-update whose new leaf carries this client's CURRENT
    /// credential — the one it was built with, or last handed through
    /// [`Self::update_credential`].
    ///
    /// **Same actor, same device, same signing key, or no commit.** The leaf
    /// signature key cannot change here: the client has one signer, and the
    /// credential it holds was validated against it when it was handed in. The
    /// actor and device are compared against the leaf being renewed, so a
    /// store opened by the wrong device's credential cannot quietly re-badge a
    /// seat ([`DenyReason::UpdateOfAnotherLeaf`], the same reason every
    /// receiver gives for the same commit).
    ///
    /// Refused as well when the new credential is no fresher than the leaf's
    /// — including the identical bytes — so a caller that skipped
    /// [`Self::credential_refresh_due`] still cannot spend an epoch on
    /// nothing.
    ///
    /// The proposal store is NOT swept in, as for [`Self::replace_member`]: a
    /// renewal is a repair and should carry nothing anybody else queued. That
    /// is also what lets a receiver recognise it — a commit with no proposals
    /// and one new leaf for its own sender — which is the only commit a leaf
    /// whose credential has already lapsed may still make
    /// (docs/identity.md §Refreshing a seated leaf).
    ///
    /// **Staged, not merged**, like every other commit here.
    pub fn refresh_credential(&mut self, group_id: &[u8]) -> Result<CommitBundle> {
        self.synced(|client| {
            let outcome = client.stage_refreshed_credential(group_id);
            client.stage_committed(group_id, outcome)
        })
    }

    fn stage_refreshed_credential(&mut self, group_id: &[u8]) -> Result<CommitBundle> {
        self.rules
            .evaluate(&self.own_context(ProposalKind::Update))
            .into_result()?;
        {
            let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
            if !group.is_active() {
                return Err(Error::NotAMember);
            }
        }
        // Checked against the clock NOW, not only when it was handed in: a
        // client opened on a credential that has since expired must not carry
        // an expired credential into a leaf that every receiver then refuses.
        let fresh = self.identity_provider.validate_credential(
            &self.credential_with_key.credential,
            self.credential_with_key.signature_key.as_slice(),
        )?;
        let seated = self.own_leaf_credential(group_id)?;
        if seated.payload().actor_id != fresh.actor_id
            || seated.payload().device_id != fresh.device_id
            || seated.device_key() != &fresh.device_key
            || seated.account().map(|(key, _)| *key) != fresh.account_key
        {
            return Err(Error::PolicyRefused(DenyReason::UpdateOfAnotherLeaf));
        }
        // A renewal that only carries today's capabilities may hand in the
        // same credential; every other renewal must bring a fresher one.
        // So may a periodic rotation: the new HPKE key is the point, and the
        // credential may be the one the leaf already has.
        let same_allowed =
            self.leaf_capabilities_stale(group_id)? || self.leaf_rotation_due(group_id)?;
        if fresh.expires_at < seated.payload().exp
            || (fresh.expires_at == seated.payload().exp && !same_allowed)
        {
            return Err(Error::invalid(
                "this device holds no credential fresher than the one its leaf already carries",
            ));
        }
        // Past the grace every receiver refuses the renewal, while the
        // delivery service (which reads no credentials) accepts it — so
        // building one would fork this device off the group. See
        // `leaf_credential_past_grace`.
        if self.leaf_credential_past_grace(group_id)? {
            return Err(Error::CredentialRejected(CredentialRejection::Expired));
        }
        let credential_with_key = self.credential_with_key.clone();
        let bundle = self.stage_leaf_credential(group_id, credential_with_key)?;
        // The receivers' own verdict on the renewal just staged, which the
        // check above cannot quite be: the renewal's own leaf is in the tree
        // clock the receivers judge it at, and the grace test here reads it
        // too. Cleared if refused, so nothing is left pending.
        self.refuse_own_commit_receivers_would_refuse(group_id)?;
        Ok(bundle)
    }

    /// A renewal carrying ANY token, with none of [`Self::refresh_credential`]'s
    /// own checks — so a test can hand every other member a commit that
    /// re-badges a seat, or renews it with an expired credential, and prove
    /// they refuse it. The token must still bind this client's signing key,
    /// since the leaf is signed with it. See `test-forgery` in Cargo.toml.
    #[cfg(feature = "test-forgery")]
    #[doc(hidden)]
    pub fn forge_refresh_credential(
        &mut self,
        group_id: &[u8],
        token: &[u8],
    ) -> Result<CommitBundle> {
        let credential_with_key = CredentialWithKey {
            credential: Credential::from(BasicCredential::new(token.to_vec())),
            signature_key: self.signer.public().to_vec().into(),
        };
        self.synced(|client| {
            let outcome = client.stage_leaf_credential(group_id, credential_with_key);
            client.stage_committed(group_id, outcome)
        })
    }

    /// Stage the renewal commit itself: no proposals, a forced update path,
    /// and a new leaf carrying `credential_with_key`.
    fn stage_leaf_credential(
        &mut self,
        group_id: &[u8],
        credential_with_key: CredentialWithKey,
    ) -> Result<CommitBundle> {
        // Today's capabilities ride every renewal, which is how a leaf seated
        // without `peachy_group_meta` learns to carry it
        // ([`Self::leaf_capabilities_stale`]).
        let capabilities = self.leaf_capabilities();
        let plan = CommitPlan {
            own_leaf_growth: own_leaf_growth(
                self.groups.get(group_id).ok_or(Error::NoSuchGroup)?,
                credential_with_key.credential.tls_serialized_len(),
                capabilities.tls_serialized_len(),
            ),
            ..CommitPlan::default()
        };
        let parameters = LeafNodeParameters::builder()
            .with_credential_with_key(credential_with_key)
            .with_capabilities(capabilities)
            .build();
        let bundle = self.padded_commit(group_id, &plan, |this| {
            let provider = &this.provider;
            let signer = &this.signer;
            let group = this.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            group
                .commit_builder()
                .consume_proposal_store(false)
                .force_self_update(true)
                .leaf_node_parameters(parameters)
                .load_psks(provider.storage())
                .map_err(mls_err)?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(mls_err)?
                .stage_commit(provider)
                .map_err(mls_err)
        })?;
        let commit = bundle.commit().to_bytes().map_err(mls_err)?;
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        // STAGED, NOT MERGED. See §The commit lifecycle.
        Ok(CommitBundle {
            commit,
            welcome: None,
            epoch: group.epoch().as_u64() + 1,
        })
    }

    /// The `pdc1` on this device's own leaf, parsed but NOT validated
    /// — a lapsed one is exactly what the refresh path needs to read.
    fn own_leaf_credential(&self, group_id: &[u8]) -> Result<DeviceCredential> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        let own = group.own_leaf_index();
        let member = group
            .members()
            .find(|member| member.index == own)
            .ok_or(Error::NotAMember)?;
        let basic = BasicCredential::try_from(member.credential)
            .map_err(|_| Error::from(CredentialRejection::WrongCredentialType))?;
        DeviceCredential::parse(basic.identity())
    }

    /// Whether two identities are the same SEAT: one actor, one device, one
    /// signing key. What a renewed leaf must keep — and, checked beside it
    /// where a leaf is renewed ([`Self::check_renewed_leaf`]), one account
    /// identity key.
    fn same_seat(old: &PeachyIdentity, new: &PeachyIdentity) -> bool {
        old.actor_id == new.actor_id
            && old.device_id == new.device_id
            && old.device_key == new.device_key
    }

    /// A leaf a member is about to swap in for its own — through a commit's
    /// update path, or an Update proposal — checked as a RECEIVED leaf
    /// ([`Self::received_leaf_at`]: the grace, no not-before check), then that it
    /// is the same seat, then that its credential expires no earlier than the
    /// one it replaces.
    ///
    /// Not strictly, because a strict check forks the group: it would ask "is
    /// this credential live NOW", and "now" is when this receiver got round to
    /// the commit, not when it was made. A phone offline across the leaf's
    /// `exp` would refuse on catch-up the commit everybody else had merged.
    /// What keeps a renewal honest instead is the MONOTONIC rule:
    /// the new `exp` must be at least the old one, so a commit can hand in the
    /// same credential (every key rotation does) or a fresher one, and never
    /// wind a seat back to a credential that lapsed before the one it held.
    /// That rule is also what bounds dropping the not-before check — a
    /// renewal's `iat` may read as the future on a slow clock, but its `exp`
    /// is pinned below by a credential this receiver already accepted.
    ///
    /// A regressing credential is refused as `Expired`: relative to the seat
    /// it would replace, it is.
    ///
    /// Before this existed nothing looked at an updated leaf's credential at
    /// all; OpenMLS verifies the leaf's signature and leaves "is this the same
    /// client" to the application (RFC 9420 §7.9.2 and §12.1.2). An update
    /// that keeps the credential compares a credential with itself.
    fn check_renewed_leaf(
        identity_provider: &PeachyIdentityProvider,
        sender: &PeachyIdentity,
        leaf: &LeafNode,
        at: i64,
    ) -> Result<PeachyIdentity> {
        let renewed = Self::received_leaf_at(identity_provider, leaf, at)?;
        if !Self::same_seat(sender, &renewed) || sender.account_key != renewed.account_key {
            return Err(Error::PolicyRefused(DenyReason::UpdateOfAnotherLeaf));
        }
        if renewed.expires_at < sender.expires_at {
            return Err(CredentialRejection::Expired.into());
        }
        Ok(renewed)
    }

    /// The identity of a leaf that arrives inside ANOTHER member's commit or
    /// Welcome — an update path's leaf, a by-reference Update's leaf, an added
    /// key package: every check but two. Its credential
    /// may have lapsed up to
    /// [`EXPIRED_LEAF_GRACE_SECONDS`](crate::identity::EXPIRED_LEAF_GRACE_SECONDS)
    /// ago, and an `iat` in this reader's future is not refused
    /// ([`PeachyIdentityProvider::validate_seated_credential`] says why).
    ///
    /// Both relaxations are about the same thing: a commit is judged by every
    /// member at a different moment on a different clock, and a check whose
    /// answer depends on which is a fork. The committer's own checks, made
    /// once on one clock, stay strict (`add_member`, `replace_member`,
    /// `refresh_credential`).
    ///
    /// The grace is measured from `at` — the tree clock — rather than from
    /// this reader's wall. Past the grace at `at` is past it for every member.
    fn received_leaf_at(
        identity_provider: &PeachyIdentityProvider,
        leaf: &LeafNode,
        at: i64,
    ) -> Result<PeachyIdentity> {
        identity_provider
            .validate_seated_credential_at(
                leaf.credential(),
                leaf.signature_key().as_slice(),
                crate::identity::EXPIRED_LEAF_GRACE_SECONDS,
                at,
            )
            .map(|(identity, _lapsed)| identity)
    }

    /// When this device holds its sender's account's signed revocation of
    /// the sender's device key, the second the delivery service said it took
    /// effect, `0` when it did not say; `None` when it holds none
    /// (crate::revocation §A revoked key's messages). The kept signature is
    /// verified again here under the account key the sender's own credential
    /// names, so a stored entry speaks only for the account that signed it.
    fn sender_revoked_at(
        storage: &crate::storage::PeachyStorage,
        sender: &PeachyIdentity,
    ) -> Result<Option<i64>> {
        let Some(account_key) = sender.account_key else {
            return Ok(None);
        };
        let Some((signature, revoked_at)) = storage.peer_revocation(&sender.device_key)? else {
            return Ok(None);
        };
        Ok(crate::revocation::verify_device_revocation(
            &account_key,
            &sender.device_key,
            &signature,
        )
        .then_some(revoked_at))
    }

    /// THE TREE CLOCK: the latest `iat` signed into any PERSON's leaf of
    /// `group`'s current tree, or into any person's leaf `staged` would bring
    /// in (its update path's leaf, a swept-up Update's leaf, an added key
    /// package's leaf), read by
    /// [`PeachyIdentityProvider::claimed_issued_at`].
    ///
    /// The "now" a verdict on a received commit is judged at. Every member at
    /// an epoch holds the same tree and reads the same commit, and every `iat`
    /// is the issuer's signature and nobody's wall, so every member computes
    /// the same number — which a wall clock cannot give, since a receiver
    /// catching up a week late or running a day slow reads another one. In an
    /// honest group it only LAGS real time (an issuer signs `iat = now`), so a
    /// leaf the tree clock calls lapsed has lapsed for real. It is NOT
    /// monotonic: it is a max over the leaves present, so a commit that
    /// removes the leaf with the newest `iat` moves it back, and a leaf it
    /// called lapsed can read as live again. That is deterministic — every
    /// member computes the same smaller number — so it forks nobody; what it
    /// costs is written down in docs/identity.md §A received commit is
    /// judged on the tree clock.
    ///
    /// Capped from above twice: no credential may claim to live longer than
    /// [`MAX_CREDENTIAL_LIFETIME_SECONDS`](crate::identity::MAX_CREDENTIAL_LIFETIME_SECONDS),
    /// and no commit may carry the clock forward by
    /// [`MAX_TREE_CLOCK_JUMP_SECONDS`](crate::identity::MAX_TREE_CLOCK_JUMP_SECONDS)
    /// or more ([`Self::refuse_tree_clock_jump`]).
    ///
    /// An `iat` from a leaf the commit introduces is read before that leaf is
    /// verified. That cannot help a forger: a commit carrying a leaf that
    /// fails verification is refused whole a few lines later, and a larger
    /// clock only ever makes the verdict on a lapsed committer STRICTER.
    fn tree_clock(group: &MlsGroup, staged: Option<&openmls::prelude::StagedCommit>) -> i64 {
        let tree = group
            .members()
            .filter_map(|member| PeachyIdentityProvider::claimed_issued_at(&member.credential));
        let mut clock = tree.max().unwrap_or(i64::MIN);
        if let Some(staged) = staged {
            for credential in Self::introduced_credentials(staged) {
                if let Some(iat) = PeachyIdentityProvider::claimed_issued_at(&credential) {
                    clock = clock.max(iat);
                }
            }
        }
        clock
    }

    /// The credential of every leaf `staged` brings into the tree: its update
    /// path's leaf, each swept-up Update's leaf, each added key package's
    /// leaf. Cloned, because OpenMLS hands the queued proposals out as
    /// short-lived wrappers.
    fn introduced_credentials(staged: &openmls::prelude::StagedCommit) -> Vec<Credential> {
        staged
            .update_path_leaf_node()
            .map(|leaf| leaf.credential().clone())
            .into_iter()
            .chain(
                staged
                    .update_proposals()
                    .map(|update| update.update_proposal().leaf_node().credential().clone()),
            )
            .chain(staged.add_proposals().map(|add| {
                add.add_proposal()
                    .key_package()
                    .leaf_node()
                    .credential()
                    .clone()
            }))
            .collect()
    }

    /// NO COMMIT MAY CARRY THE TREE CLOCK FORWARD BY
    /// [`MAX_TREE_CLOCK_JUMP_SECONDS`](crate::identity::MAX_TREE_CLOCK_JUMP_SECONDS)
    /// OR MORE: a commit is refused as
    /// `Expired` if any leaf it brings in claims an `iat` that far past `clock_before`, the tree clock taken
    /// before the commit.
    ///
    /// Receivers skip the not-before check on a leaf that arrives in a commit
    /// (a slow reader would fork on it), so without this nothing would stop a
    /// commit bringing in a leaf issued years ahead — and every other leaf is
    /// then past its grace on the tree clock, every later commit is refused,
    /// and the group's membership is frozen for good. Below the bound the
    /// group's newest person leaf is still short of its renewal cutoff (its
    /// grace less a day) on the new clock and can renew, so the group always
    /// keeps a member who can renew.
    ///
    /// Run by every receiver and, identically, by the committer on the commit
    /// it just staged, so the two cannot disagree.
    fn refuse_tree_clock_jump(
        clock_before: i64,
        staged: &openmls::prelude::StagedCommit,
    ) -> Result<()> {
        if clock_before == i64::MIN {
            // A tree with no person leaf has no clock to jump from, and no
            // member who could have built this commit.
            return Ok(());
        }
        let ceiling = clock_before.saturating_add(crate::identity::MAX_TREE_CLOCK_JUMP_SECONDS);
        for credential in Self::introduced_credentials(staged) {
            let Ok(basic) = BasicCredential::try_from(credential) else {
                continue;
            };
            let Ok(token) = DeviceCredential::parse(basic.identity()) else {
                // Refused whole by its own verification a few lines later.
                continue;
            };
            if token.payload().iat >= ceiling {
                return Err(CredentialRejection::Expired.into());
            }
        }
        Ok(())
    }

    /// A LAPSED COMMITTER MAY ONLY RENEW — judged on the tree clock, so every
    /// receiver and the committer itself reach the same verdict.
    ///
    /// Lapsed means the committer's credential expired at or before
    /// `tree_clock`. Such a commit is taken only if it carries no proposals at
    /// all and does carry an update path: a renewal ([`Self::refresh_credential`])
    /// or a bare key rotation, neither of which touches anybody else's seat or
    /// the group's context. Everything else — a Remove, an Add, a rename —
    /// is refused as `Expired`.
    ///
    /// This lives on the RECEIVING side, judged on the tree clock. Judging
    /// "lapsed" on a receiver's wall clock would fork whoever caught up late,
    /// and leaving the rule to the committer's own client is no answer: a
    /// client-side rule binds only honest clients. A stolen phone whose
    /// credential RegisterDevice stopped renewing — revoked — could run a
    /// modified build, skip its own check and, for the whole 56-day grace,
    /// remove every leaf in every group it sat in, or rename every group.
    /// `SubmitCommit`'s `senderDeviceId` is the caller's claim and is not tied
    /// to the MLS leaf, so the delivery service cannot stop it either. The
    /// tree clock gives the receiving side a verdict with no wall in it.
    fn refuse_lapsed_committer(
        committer_expires_at: i64,
        tree_clock: i64,
        staged: &openmls::prelude::StagedCommit,
    ) -> Result<()> {
        let lapsed = committer_expires_at <= tree_clock;
        let renews_only =
            staged.queued_proposals().next().is_none() && staged.update_path_leaf_node().is_some();
        if lapsed && !renews_only {
            return Err(CredentialRejection::Expired.into());
        }
        Ok(())
    }

    /// Refuse to build a second commit while one is staged: two commits from
    /// one device against one epoch is a fork. OpenMLS's own add, remove and
    /// self-update refuse it; the commit builder they are built on here does
    /// not, so it is asked here, and the caller resolves the first commit.
    ///
    /// A HELD group ([`Self::group_hold`]) builds no commit either: its
    /// device waits for the steward's repair or veto, and a commit of its own
    /// would race it.
    fn refuse_if_commit_staged(&self, group_id: &[u8]) -> Result<()> {
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if group.pending_commit().is_some() {
            return Err(Error::Mls(
                "a commit is already staged in this group; merge or clear it first".into(),
            ));
        }
        if self.group_hold(group_id)?.is_some() {
            return Err(Error::Mls(
                "this group is held for its steward's repair or veto; no commit until it is \
                 released"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Build a commit with its content padded to the length every member
    /// would pad the same commit to, wherever its leaf sits
    /// ([`crate::commit_padding`]), and put the message block back after.
    ///
    /// OpenMLS pads a `PrivateMessage` up to a multiple of the group's stored
    /// `padding_size`, and every commit here is a `PrivateMessage`; so the
    /// stored padding is the commit's target for this one build, and every
    /// other stored setting is left as it was. Whatever `build` returns, the
    /// stored config is put back exactly after it (and [`Self::encrypt`]
    /// would restore the message block before any message in any case).
    fn padded_commit<T>(
        &mut self,
        group_id: &[u8],
        plan: &CommitPlan,
        build: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let original = {
            let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
            let target = commit_padding_target(group, plan)?;
            let original = group.configuration().clone();
            group
                .set_configuration(
                    self.provider.storage(),
                    &join_config_with_padding(&original, target)?,
                )
                .map_err(|err| Error::Mls(format!("could not set commit padding: {err}")))?;
            original
        };
        let built = build(self);
        if let Some(group) = self.groups.get_mut(group_id) {
            group
                .set_configuration(self.provider.storage(), &original)
                .map_err(|err| Error::Mls(format!("could not set group padding: {err}")))?;
        }
        built
    }

    /// Refuse to SEAL an application message on a leaf a receiver judges
    /// lapsed ([`crate::identity::judge_message_sender`]): one whose `exp` is
    /// at or before this epoch's tree clock, or that this device's own wall
    /// puts within [`crate::identity::CLOCK_SKEW_SECONDS`] of its `exp` or
    /// past it. A receiver calls a message new once the delivery service
    /// received it at or after `exp`, and the service's clock may run that
    /// far ahead of this one, so the sender stops first. An honest sender
    /// learns it here, loudly, as a failed send, rather than from a silence;
    /// the renewal every client runs before a send
    /// ([`Self::credential_refresh_due`]) is what keeps a live device from
    /// reaching it, and is what the app runs before it sends again. A leaf
    /// whose credential this device cannot read is not judged: receivers
    /// judge it anyway. docs/identity.md §A lapsed leaf's new
    /// messages.
    fn refuse_to_seal_on_lapsed_leaf(&self, group_id: &[u8]) -> Result<()> {
        #[cfg(feature = "test-forgery")]
        if self.sends_while_lapsed {
            return Ok(());
        }
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if !group.is_active() {
            return Ok(());
        }
        let Ok(credential) = self.own_leaf_credential(group_id) else {
            return Ok(());
        };
        let exp = credential.payload().exp;
        let own_wall = self
            .identity_provider
            .now_unix()
            .saturating_add(crate::identity::CLOCK_SKEW_SECONDS);
        if own_wall >= exp || Self::tree_clock(group, None) >= exp {
            return Err(CredentialRejection::Expired.into());
        }
        Ok(())
    }

    /// Refuse to BUILD a commit from a leaf whose own credential has lapsed —
    /// on this device's own clock, or on the group's tree clock.
    ///
    /// The committer-side half of "a lapsed leaf may renew and nothing else",
    /// run before anything is built. Its own clock catches the honest device
    /// that simply let its credential run out; the tree clock catches the
    /// device whose clock runs slow while the group has moved past its `exp`
    /// — which every receiver would refuse (`refuse_lapsed_committer`), so
    /// building it would only wedge this device on a commit nobody merges.
    /// [`Self::refresh_credential`] is the one commit it does not guard.
    fn refuse_if_own_leaf_lapsed(&self, group_id: &[u8]) -> Result<()> {
        let exp = self.own_leaf_credential(group_id)?.payload().exp;
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if self.identity_provider.now_unix() >= exp || Self::tree_clock(group, None) >= exp {
            return Err(CredentialRejection::Expired.into());
        }
        Ok(())
    }

    /// The group's own policy (`crate::policy`) on a staged commit: admins,
    /// and who may add, remove and rename. Run by every receiver before
    /// merging and by the committer before sending, the same function on the
    /// same inputs, so a commit one honest member would refuse never leaves an
    /// honest committer. A group with no state at all (a call link's group)
    /// is not judged. One whose state names no readable policy is judged as
    /// a group with no admin, by the committer and every receiver alike.
    ///
    /// A committer whose leaf has lapsed on the tree clock is judged as
    /// nobody ([`Self::policy_actor`]), the same as a lapsed proposer: no
    /// admin's authority outlives the credential that names the admin.
    ///
    /// EVERY PROPOSAL IS JUDGED AS ITS OWN SENDER'S. A proposal the commit
    /// carries inline is the committer's (`committer`, `committer_actor`); one
    /// it names by reference keeps the sender who proposed it, and is judged
    /// as that member's, never as the committer's. The commit is refused whole
    /// if any sender's share is. The proposal rules already refuse every
    /// proposal by reference, before this runs; this is the rule that would
    /// still hold if one got this far.
    fn refuse_by_group_policy(
        identity_provider: &PeachyIdentityProvider,
        group: &MlsGroup,
        staged: &openmls::prelude::StagedCommit,
        committer: LeafNodeIndex,
        committer_actor: &str,
        tree_clock: i64,
    ) -> Result<()> {
        let prior = group_meta_from_context(group.extensions());
        if prior.is_none() {
            return Ok(());
        }
        // Who a seated leaf's credential names, with the grace, at the tree
        // clock, or `None` when it identifies nobody.
        let identity_at = |index: LeafNodeIndex| -> Option<PeachyIdentity> {
            group
                .members()
                .find(|member| member.index == index)
                .and_then(|member| {
                    identity_provider
                        .validate_seated_credential_at(
                            &member.credential,
                            &member.signature_key,
                            crate::identity::EXPIRED_LEAF_GRACE_SECONDS,
                            tree_clock,
                        )
                        .ok()
                        .filter(|(_, lapsed)| !lapsed)
                        .map(|(identity, _)| identity)
                })
        };
        let actor_at = |index: LeafNodeIndex| identity_at(index).map(|identity| identity.actor_id);

        /// One sender's share of the commit.
        struct Share {
            proposer: String,
            added: Vec<crate::policy::Seat>,
            removed: Vec<crate::policy::RemovedLeaf>,
            new_meta: Option<Vec<u8>>,
        }
        let mut shares: Vec<Share> = Vec::new();
        for queued in staged.queued_proposals() {
            let proposer = match queued.sender() {
                openmls::prelude::Sender::Member(index) if *index == committer => {
                    committer_actor.to_owned()
                }
                // Somebody else's proposal, named by reference. A proposer
                // nobody can identify cannot be judged, so neither can the
                // commit.
                openmls::prelude::Sender::Member(index) => {
                    actor_at(*index).ok_or(Error::PolicyRefused(DenyReason::NonMemberProposal))?
                }
                _ => return Err(Error::PolicyRefused(DenyReason::ExternalSender)),
            };
            let position = match shares.iter().position(|share| share.proposer == proposer) {
                Some(position) => position,
                None => {
                    shares.push(Share {
                        proposer,
                        added: Vec::new(),
                        removed: Vec::new(),
                        new_meta: None,
                    });
                    shares.len() - 1
                }
            };
            let share = &mut shares[position];
            match queued.proposal() {
                openmls::prelude::Proposal::Add(add) => {
                    // An unidentifiable added leaf is refused whole elsewhere;
                    // here it only needs a seat to be judged by, and has
                    // none.
                    let seat = Self::received_leaf_at(
                        identity_provider,
                        add.key_package().leaf_node(),
                        tree_clock,
                    )
                    .map(Self::seat_of)
                    .unwrap_or_default();
                    share.added.push(seat);
                }
                openmls::prelude::Proposal::Remove(remove) => {
                    share.removed.push(match identity_at(remove.removed()) {
                        Some(identity) => crate::policy::RemovedLeaf {
                            actor: Some(identity.actor_id),
                            device: Some(identity.device_id),
                            account_key: identity.account_key,
                            device_key: Some(identity.device_key),
                        },
                        None => crate::policy::RemovedLeaf::of_actor(None),
                    });
                }
                openmls::prelude::Proposal::GroupContextExtensions(gce)
                    if share.new_meta.is_none() =>
                {
                    share.new_meta = group_meta_from_context(gce.extensions());
                }
                _ => {}
            }
        }
        for share in &shares {
            let facts = crate::policy::CommitFacts {
                prior_meta: prior.as_deref(),
                sender: &share.proposer,
                added: share.added.clone(),
                removed: share.removed.clone(),
                new_meta: share.new_meta.as_deref(),
            };
            let decision = crate::policy::judge_commit(&facts);
            if let PolicyDecision::Deny(reason) = decision {
                return Err(Error::PolicyRefused(reason));
            }
            // A reseat under another device key passes the policy as a
            // reseat; the receiver judges it on its own, in every group,
            // policy or none (`Self::rekeys_a_removed_seat`).
        }
        Ok(())
    }

    /// The seat an identity is judged by (`crate::policy::Seat`).
    fn seat_of(identity: PeachyIdentity) -> crate::policy::Seat {
        crate::policy::Seat {
            actor: identity.actor_id,
            device: Some(identity.device_id),
            account_key: identity.account_key,
            device_key: Some(identity.device_key),
        }
    }

    /// ONE PERSON, ONE ACCOUNT KEY (`crate::policy::judge_account_keys`), on
    /// a staged commit: the tree it leaves in place, the leaves it adds, and
    /// `reader`, the device judging it. Run by every receiver before merging
    /// and by the committer before sending, in every group, policy or not.
    ///
    /// Each leaf is read with every credential check but the clock, as
    /// [`Self::seated_identity`] reads one: whose a leaf is, and under which
    /// account key, does not stop being true on its `exp`, and a verdict with
    /// no clock in it cannot differ between two members. A leaf no check
    /// reads is left out; one the commit adds is then refused whole a few
    /// lines later.
    fn refuse_account_key_conflict(
        identity_provider: &PeachyIdentityProvider,
        group: &MlsGroup,
        staged: &openmls::prelude::StagedCommit,
        reader: &PeachyIdentity,
    ) -> Result<()> {
        let removed: Vec<LeafNodeIndex> = staged
            .remove_proposals()
            .map(|proposal| proposal.remove_proposal().removed())
            .collect();
        let kept: Vec<crate::policy::Seat> = group
            .members()
            .filter(|member| !removed.contains(&member.index))
            .filter_map(|member| {
                identity_provider
                    .validate_seated_credential(&member.credential, &member.signature_key, i64::MAX)
                    .ok()
            })
            .map(|(identity, _)| Self::seat_of(identity))
            .collect();
        let added: Vec<crate::policy::Seat> = staged
            .add_proposals()
            .filter_map(|add| {
                let leaf = add.add_proposal().key_package().leaf_node();
                identity_provider
                    .validate_seated_credential(
                        leaf.credential(),
                        leaf.signature_key().as_slice(),
                        i64::MAX,
                    )
                    .ok()
            })
            .map(|(identity, _)| Self::seat_of(identity))
            .collect();
        let reader = reader
            .account_key
            .as_ref()
            .map(|key| (reader.actor_id.as_str(), key));
        match crate::policy::judge_account_keys(reader, &kept, &added) {
            PolicyDecision::Allow => Ok(()),
            PolicyDecision::Deny(reason) => Err(Error::PolicyRefused(reason)),
        }
    }

    /// The size caps on a staged commit
    /// ([`crate::policy::commit_size_refusal`]): the member leaves and
    /// accounts of the tree it leaves, and the largest leaf it brings in (its
    /// path's, each Update's, each added key package's). Run by the committer
    /// before sending, and by every receiver before merging. A leaf no check
    /// reads names no account; one the commit adds is refused anyway.
    fn commit_size_refusal(
        identity_provider: &PeachyIdentityProvider,
        group: &MlsGroup,
        staged: &openmls::prelude::StagedCommit,
    ) -> Option<String> {
        let removed: Vec<LeafNodeIndex> = staged
            .remove_proposals()
            .map(|proposal| proposal.remove_proposal().removed())
            .collect();
        let actor = |credential: &Credential, key: &[u8]| {
            identity_provider
                .validate_seated_credential(credential, key, i64::MAX)
                .ok()
                .map(|(identity, _)| identity.actor_id)
        };
        let mut leaves = 0;
        let mut accounts = std::collections::BTreeSet::new();
        for member in group.members().filter(|m| !removed.contains(&m.index)) {
            leaves += 1;
            accounts.extend(actor(&member.credential, &member.signature_key));
        }
        let mut largest = staged
            .update_path_leaf_node()
            .map_or(0, |leaf| leaf.tls_serialized_len());
        for update in staged.update_proposals() {
            largest = largest.max(update.update_proposal().leaf_node().tls_serialized_len());
        }
        for add in staged.add_proposals() {
            let leaf = add.add_proposal().key_package().leaf_node();
            leaves += 1;
            largest = largest.max(leaf.tls_serialized_len());
            accounts.extend(actor(leaf.credential(), leaf.signature_key().as_slice()));
        }
        crate::policy::commit_size_refusal(leaves, accounts.len(), largest)
    }

    /// Refuse to mint a key package whose leaf is over
    /// [`crate::policy::MAX_LEAF_NODE_BYTES`]. A commit's path leaf, the
    /// founder's included, is held to it by [`Self::commit_size_refusal`].
    fn refuse_oversized_own_leaf(leaf: &openmls::prelude::LeafNode) -> Result<()> {
        let len = leaf.tls_serialized_len();
        if len > crate::policy::MAX_LEAF_NODE_BYTES {
            return Err(Error::invalid(format!(
                "this device's leaf is {len} bytes, over {}",
                crate::policy::MAX_LEAF_NODE_BYTES
            )));
        }
        Ok(())
    }

    /// The actor the group's policy judges a committer as: its own, or `""`
    /// (unidentified, never an admin, `crate::policy`) once its credential
    /// has expired at `tree_clock`. Fails closed. A lapsed committer may only
    /// renew anyway ([`Self::refuse_lapsed_committer`]), which the policy has
    /// nothing to say about; this keeps the policy from ever being the place
    /// a lapsed admin is still one.
    fn policy_actor(actor: &str, expires_at: i64, tree_clock: i64) -> &str {
        if expires_at <= tree_clock {
            ""
        } else {
            actor
        }
    }

    /// The receivers' verdict on the commit this device just STAGED, run by
    /// the committer before the commit leaves: the same function on the same
    /// tree and the same commit, so a commit that passes here passes on every
    /// member. It matters where the commit brings in a leaf newer than this
    /// device's `exp` — a key package minted after it, say — which moves the
    /// tree clock past what [`Self::refuse_if_own_leaf_lapsed`] could see.
    /// A refused commit is cleared, so nothing is left pending.
    fn refuse_own_commit_receivers_would_refuse(&mut self, group_id: &[u8]) -> Result<()> {
        let exp = self.own_leaf_credential(group_id)?.payload().exp;
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        let verdict = match group.pending_commit() {
            Some(staged) => Self::refuse_tree_clock_jump(Self::tree_clock(group, None), staged)
                .and_then(|()| {
                    let clock = Self::tree_clock(group, Some(staged));
                    // The receivers' first test: the committer's grace, on
                    // the clock this commit leaves the tree at.
                    if clock >= exp.saturating_add(crate::identity::EXPIRED_LEAF_GRACE_SECONDS) {
                        return Err(CredentialRejection::Expired.into());
                    }
                    Self::refuse_lapsed_committer(exp, clock, staged)
                })
                .and_then(|()| {
                    // The proposal rules, as a receiver runs them.
                    let contexts: Vec<ProposalContext> = staged
                        .queued_proposals()
                        .map(|queued| {
                            Self::proposal_context(&self.identity_provider, group, queued)
                        })
                        .collect();
                    self.rules.evaluate_all(contexts.iter()).into_result()
                })
                .and_then(|()| {
                    let clock = Self::tree_clock(group, Some(staged));
                    Self::refuse_by_group_policy(
                        &self.identity_provider,
                        group,
                        staged,
                        group.own_leaf_index(),
                        Self::policy_actor(&self.identity.actor_id, exp, clock),
                        clock,
                    )
                })
                .and_then(|()| {
                    Self::refuse_account_key_conflict(
                        &self.identity_provider,
                        group,
                        staged,
                        &self.identity,
                    )
                })
                .and_then(|()| {
                    match Self::commit_size_refusal(&self.identity_provider, group, staged) {
                        Some(reason) => Err(Error::invalid(reason)),
                        None => Ok(()),
                    }
                }),
            None => Ok(()),
        };
        if verdict.is_err() {
            group
                .clear_pending_commit(self.provider.storage())
                .map_err(|err| Error::Mls(err.to_string()))?;
        }
        verdict
    }

    // ---- Messages -----------------------------------------------------------

    /// Encrypt an application message under the default content hint
    /// ([`crate::hint::CONTENT_HINT_DEFAULT`]: show the loss).
    ///
    /// Every application message this core sends carries a hint: a message
    /// with none has authenticated data three bytes shorter, which the server
    /// reads, so a door that sent without one would mark its sends apart from
    /// every other client's.
    ///
    /// Persists, despite reading like a pure function: encrypting advances the
    /// sender ratchet, and a generation reused after a crash is a nonce reused
    /// under the same key.
    pub fn encrypt(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with_hint(group_id, plaintext, crate::hint::CONTENT_HINT_DEFAULT)
    }

    /// An application message with NO content hint. Only for tests that play a
    /// device sending one; no door exposes it.
    #[doc(hidden)]
    pub fn encrypt_without_hint(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_padded_to(group_id, plaintext, APPLICATION_PADDING_BLOCK, Vec::new())
    }

    /// Encrypt an application message that says how a receiver who cannot
    /// open it should treat the loss (`crate::hint`): `hint` is one of the
    /// `CONTENT_HINT_*` values, carried in the message's authenticated data.
    ///
    /// After the hint comes the author's commitment
    /// (`crate::hint` §The author's commitment): to this device's person, over
    /// the secret [`crate::hint::resend_secret_of`] finds in `plaintext`, or
    /// zeros when it finds none. A receiver that cannot open the message takes
    /// an answer to its resend ask only from the person it commits to.
    pub fn encrypt_with_hint(
        &mut self,
        group_id: &[u8],
        plaintext: &[u8],
        hint: u8,
    ) -> Result<Vec<u8>> {
        if crate::hint::hint_from_aad(&crate::hint::hint_aad(hint)).is_none() {
            return Err(Error::invalid("that is not a content hint"));
        }
        let commitment = crate::hint::resend_secret_of(hint, plaintext).map(|secret| {
            crate::hint::resend_author_commitment(group_id, &self.identity.actor_id, &secret)
        });
        self.encrypt_padded_to(
            group_id,
            plaintext,
            APPLICATION_PADDING_BLOCK,
            crate::hint::hint_aad_with_commitment(hint, commitment),
        )
    }

    /// Encrypt a call signal for the MLS lane (`crate::call::session`): an
    /// application message whose `authenticated_data` is
    /// [`crate::call::CALL_LANE_AAD`], which is no content hint. The call
    /// envelope puts one lane byte ahead of the message, and that byte plus
    /// the AAD make as many bytes as a hinted message's AAD, so a call signal
    /// is exactly as long as a message, reaction or receipt whose plaintext
    /// falls in the same padding block.
    pub(crate) fn encrypt_call_signal(
        &mut self,
        group_id: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        self.encrypt_padded_to(
            group_id,
            plaintext,
            APPLICATION_PADDING_BLOCK,
            crate::call::CALL_LANE_AAD.to_vec(),
        )
    }

    /// Encrypt exactly as a build from before [`APPLICATION_PADDING_BLOCK`]
    /// did: no padding at all. A test door and nothing else — it exists so
    /// `mls/core/tests/padding.rs` can prove a new receiver still opens what an
    /// old sender wrote, which no amount of padded traffic can show. Behind
    /// `fixture`, and exported through no binding.
    #[cfg(feature = "fixture")]
    #[doc(hidden)]
    pub fn encrypt_unpadded(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_padded_to(group_id, plaintext, 0, Vec::new())
    }

    fn encrypt_padded_to(
        &mut self,
        group_id: &[u8],
        plaintext: &[u8],
        padding: usize,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.synced(|client| client.encrypt_padded_now(group_id, plaintext, padding, aad))
    }

    fn encrypt_padded_now(
        &mut self,
        group_id: &[u8],
        plaintext: &[u8],
        padding: usize,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.refuse_to_seal_on_lapsed_leaf(group_id)?;
        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        if !group.is_active() {
            return Err(Error::NotAMember);
        }
        // A group created or joined before padding existed has its join
        // config in the store with `padding_size` 0, and OpenMLS reads the
        // STORED config, not `join_config()`. Upgrade it once, here, so every
        // sender pads from its first message after updating — whatever the
        // group's age. It only touches this device's own sending; receivers
        // need nothing (see APPLICATION_PADDING_BLOCK).
        if group.configuration().padding_size() != padding {
            group
                .set_configuration(
                    self.provider.storage(),
                    &Self::join_config_padded_to(padding),
                )
                .map_err(|err| Error::Mls(format!("could not set group padding: {err}")))?;
        }
        // The AAD applies to the next outgoing message only, and OpenMLS
        // resets it once that message is built; a refusal before then would
        // leave it for whatever this group sends next, so it is cleared by
        // hand on the error path.
        group.set_aad(aad);
        let created = group.create_message(&self.provider, &self.signer, plaintext);
        if created.is_err() {
            group.set_aad(Vec::new());
        }
        let bytes = created.map_err(mls_err)?.to_bytes().map_err(mls_err)?;
        // One more frame sealed on this leaf (LEAF_ROTATION_FRAME_BUDGET).
        let (at, sent) = match self.provider.peachy_storage().leaf_rotation(group_id)? {
            Some(record) => record,
            None => (self.own_leaf_issued_at(group_id)?, 0),
        };
        self.provider
            .peachy_storage()
            .set_leaf_rotation(group_id, at, sent.saturating_add(1))?;
        // The sending ratchet advanced past the key this message used; the
        // old ratchet state is erased, not just replaced.
        self.flushed_and_erased(bytes)
    }

    /// Process one incoming message: application, proposal or commit. Private:
    /// every caller comes through a door ([`Client::process_message`],
    /// [`Client::process_commit`]), which refuses the wrong kind before the
    /// engine reads it.
    ///
    /// Every outcome persists something — a decrypted application message
    /// advanced a receiver ratchet, a queued proposal is in the store, a merged
    /// commit is a new epoch — so the flush is around the whole thing rather
    /// than per branch. It runs even on a refusal: OpenMLS may have written
    /// before the policy layer said no, and a half-written refusal is the one
    /// state nothing can reason about.
    ///
    /// And the erase follows the flush for the same reason: a merged commit
    /// replaced an epoch's secrets, and an opened application message spent a
    /// ratchet key, and either one left on the medium is what a seized store
    /// would give back (§Storage).
    fn process_any(&mut self, group_id: &[u8], message: &[u8]) -> Result<Incoming> {
        self.synced(|client| {
            let mut outcome = client.process_inner(group_id, message, 0);
            if let Err(err) = client.flushed_and_erased(()) {
                if let Ok(incoming) = &mut outcome {
                    incoming.wipe_words();
                }
                return Err(err);
            }
            outcome
        })
    }

    /// [`Self::process_any`], all or nothing: an outcome that is not `Ok`
    /// leaves the store and the group as they were before the call. The
    /// door's writes since the write lock was taken (a ratchet OpenMLS
    /// saved, the record of what opened, a peer heard from) are rolled back,
    /// and the group in memory, whose ratchet OpenMLS advanced as it
    /// decrypted, is loaded again from the store.
    ///
    /// For application messages ([`Self::process_application`]): no state
    /// forks on whether one member read a message, so a refusal has nothing
    /// to keep, and keeping it spent a key a forged copy had no right to.
    /// A refused tag, a refused signature and a refusal of ours after both
    /// held (a sender the group has removed, a lapsed credential) all read
    /// the same way: the key is still there for the real message.
    ///
    /// `keep_as`: the mailbox envelope id an application message that opens
    /// is kept under, in this same write ([`Self::process_message_as`]). A
    /// keep that fails refuses the message as any other step would: the key
    /// is not spent.
    fn process_whole(
        &mut self,
        group_id: &[u8],
        message: &[u8],
        keep_as: Option<&str>,
        received_at: i64,
    ) -> Result<Incoming> {
        self.synced(|client| {
            let outcome = client
                .process_inner(group_id, message, received_at)
                .map_err(|err| client.replaced_device_loss(message, err))
                .and_then(|mut incoming| {
                    let mut checked = Ok(());
                    if let Incoming::Application {
                        sender, plaintext, ..
                    } = &incoming
                    {
                        checked = client.check_seal_author(message, group_id, sender);
                        if checked.is_err() {
                            client.note_seal_refused(message);
                        } else if let Some(id) = keep_as {
                            checked = client.keep_opened(id, group_id, message, sender, plaintext);
                        }
                    }
                    // A message refused after it opened is wiped before it
                    // drops: only a message handed back leaves unwiped.
                    match checked {
                        Ok(()) => Ok(incoming),
                        Err(err) => {
                            incoming.wipe_words();
                            Err(err)
                        }
                    }
                });
            match outcome {
                Ok(mut incoming) => match client.flushed_and_erased(()) {
                    Ok(()) => Ok(incoming),
                    Err(err) => {
                        incoming.wipe_words();
                        Err(err)
                    }
                },
                Err(err) => {
                    client.undo_message(group_id);
                    Err(err)
                }
            }
        })
    }

    /// A message inside an envelope granted on a DEVICE SEAL
    /// ([`Self::next_reopenable`]), found by its own SHA-256, must be by the
    /// device a seal granting it named: a seal is a member's word, and one
    /// member must not pass another's message off as its own seal's. Refused
    /// as [`Error::NotFromAMember`] (silence: acknowledged, nothing shown),
    /// inside the write that would spend the key, so the key is not spent,
    /// when grants hold these bytes and none of them names its author; the
    /// same message granted on its author's own seal too goes through. Any
    /// other message passes.
    ///
    /// Only an application message is checked. A handshake inside a granted
    /// envelope never reaches here: the message door refuses a commit
    /// unread, and of proposals takes only a leave, which changes nothing
    /// but its sender's own leaf.
    fn check_seal_author(
        &self,
        message: &[u8],
        group_id: &[u8],
        sender: &PeachyIdentity,
    ) -> Result<()> {
        if self.seal_grants.is_empty() {
            return Ok(());
        }
        let digest: [u8; 32] = sha2::Sha256::digest(message).into();
        let mut granted = self
            .seal_grants
            .values()
            .filter(|grant| grant.inner_digest == digest)
            .peekable();
        if granted.peek().is_none() {
            return Ok(());
        }
        if granted.any(|grant| {
            grant.group_id == group_id
                && grant.sender_key.as_slice() == sender.device_key.as_slice()
        }) {
            return Ok(());
        }
        Err(Error::NotFromAMember(
            "a device seal named another device than the message's author",
        ))
    }

    /// Note the envelopes granted for `message` whose seal the author check
    /// refused ([`Self::check_seal_author`]): let go without a release note
    /// ([`Self::release_held`]).
    fn note_seal_refused(&mut self, message: &[u8]) {
        let digest: [u8; 32] = sha2::Sha256::digest(message).into();
        let refused: Vec<[u8; 32]> = self
            .seal_grants
            .iter()
            .filter(|(_, grant)| grant.inner_digest == digest)
            .map(|(envelope, _)| *envelope)
            .collect();
        self.seal_refused.extend(refused);
    }

    /// A message granted on the seal of a device whose person holds another
    /// leaf of the group (the device was replaced) that the door refuses as
    /// from no member is a loss, not silence: said as one, so the reader
    /// draws a placeholder and asks for it again, and the person's devices
    /// that remain answer.
    fn replaced_device_loss(&self, message: &[u8], err: Error) -> Error {
        if !matches!(err, Error::NotFromAMember(_)) || self.seal_grants.is_empty() {
            return err;
        }
        let digest: [u8; 32] = sha2::Sha256::digest(message).into();
        if self
            .seal_grants
            .values()
            .any(|grant| grant.inner_digest == digest && grant.by_person)
        {
            return Error::Mls(
                "sealed by a device its person has since replaced; asked for again".to_owned(),
            );
        }
        err
    }

    /// Note who each device key of the copy of `group_id` belongs to, and
    /// the epoch each key that holds no leaf any more left at
    /// ([`crate::storage::LeafPeople`]): at every epoch the copy enters. Only
    /// a key not noted before has its credential checked.
    fn note_leaf_people(&self, group_id: &[u8]) -> Result<()> {
        let Some(group) = self.groups.get(group_id) else {
            return Ok(());
        };
        let epoch = group.epoch().as_u64().max(1);
        let storage = self.provider.peachy_storage();
        let before = storage.leaf_people(group_id)?;
        let mut people = before.clone().unwrap_or_default();
        people.forgotten_at_ms = 0;
        let mut seated = std::collections::HashSet::new();
        for member in group.members() {
            let Ok(key) = <[u8; 32]>::try_from(member.signature_key.as_slice()) else {
                continue;
            };
            seated.insert(key);
            if let Some(known) = people.people.iter_mut().find(|known| known.key == key) {
                known.left_epoch = 0;
                known.left_at_ms = 0;
                continue;
            }
            let Ok((identity, _)) = self.identity_provider.validate_seated_credential(
                &member.credential,
                &member.signature_key,
                i64::MAX,
            ) else {
                continue;
            };
            people.people.push(crate::storage::LeafPerson {
                key,
                left_epoch: 0,
                left_at_ms: 0,
                actor_id: identity.actor_id,
            });
        }
        let now = u64::try_from(self.identity_provider.now_unix_ms()).unwrap_or(0);
        for person in &mut people.people {
            if person.left_epoch == 0 && !seated.contains(&person.key) {
                person.left_epoch = epoch;
                person.left_at_ms = now.max(1);
            }
            // NOTED BY A CLOCK THAT RAN AHEAD and was set back: from now, so
            // the 30 days are not stretched by however far it ran.
            if person.left_at_ms > now {
                person.left_at_ms = now.max(1);
            }
        }
        let excess = people
            .people
            .len()
            .saturating_sub(crate::storage::LEAF_PEOPLE_KEPT);
        if excess > 0 {
            let mut gone: Vec<(u64, [u8; 32])> = people
                .people
                .iter()
                .filter(|person| person.left_epoch != 0)
                .map(|person| (person.left_epoch, person.key))
                .collect();
            gone.sort();
            let dropped: std::collections::HashSet<[u8; 32]> =
                gone.into_iter().take(excess).map(|(_, key)| key).collect();
            people
                .people
                .retain(|person| !dropped.contains(&person.key));
        }
        if before.as_ref() != Some(&people) {
            storage.set_leaf_people(group_id, &people)?;
        }
        Ok(())
    }

    /// Sweep the opened messages kept for their envelope ids of those older
    /// than [`HELD_ENVELOPE_MAX_AGE_MS`] and the oldest past
    /// [`crate::storage::OPENED_CONTENT_KEPT`], when this client has not
    /// swept for [`OPENED_PRUNE_EVERY_MS`]. Inside the caller's write, which
    /// ends erased.
    fn sweep_opened_if_due(&mut self) -> Result<()> {
        let now = u64::try_from(self.identity_provider.now_unix_ms()).unwrap_or(0);
        if self
            .opened_swept_at_ms
            .is_some_and(|at| now.saturating_sub(at) < OPENED_PRUNE_EVERY_MS)
        {
            return Ok(());
        }
        self.provider.peachy_storage().prune_opened_content(
            now.saturating_sub(HELD_ENVELOPE_MAX_AGE_MS),
            crate::storage::OPENED_CONTENT_KEPT.saturating_sub(1),
        )?;
        self.opened_swept_at_ms = Some(now);
        Ok(())
    }

    /// Keep what an application message opened to under its envelope id and
    /// digest, inside the write that spends its key ([`Self::process_whole`]),
    /// sweeping the old and the excess first when that is due.
    fn keep_opened(
        &mut self,
        id: &str,
        group_id: &[u8],
        message: &[u8],
        sender: &PeachyIdentity,
        plaintext: &[u8],
    ) -> Result<()> {
        self.sweep_opened_if_due()?;
        let now = u64::try_from(self.identity_provider.now_unix_ms()).unwrap_or(0);
        self.provider.peachy_storage().keep_opened_content(
            id,
            &crate::storage::OpenedContent {
                kept_at_ms: now,
                group_id: group_id.to_vec(),
                digest: crate::storage::opened_digest(message),
                sender: sender.clone(),
                plaintext: crate::secret::Secret::new(plaintext.to_vec()),
            },
        )?;
        Ok(())
    }

    /// Discard what the store holds open since the door took the write lock
    /// ([`Self::process_whole`]), and load `group_id` again from what the
    /// store committed. Only a group held in memory is loaded: one that is
    /// not (unknown, or a leave set aside, which the store keeps out of
    /// sight) was refused before the engine touched anything, and loading it
    /// would bring it back into sight. A group the store no longer holds, or
    /// one that will not load, leaves the groups marked stale, for the next
    /// write door to load again or refuse.
    fn undo_message(&mut self, group_id: &[u8]) {
        let _ = self.provider.peachy_storage().rollback();
        if !self.groups.contains_key(group_id) {
            return;
        }
        match MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id)) {
            Ok(Some(group)) => {
                self.groups.insert(group_id.to_vec(), group);
            }
            Ok(None) | Err(_) => self.stale = true,
        }
    }

    /// `received_at` is the second the delivery service received an
    /// application message, or `0` when unknown
    /// ([`Self::process_message_received_at`]); nothing else reads it.
    fn process_inner(
        &mut self,
        group_id: &[u8],
        message: &[u8],
        received_at: i64,
    ) -> Result<Incoming> {
        let incoming = MlsMessageIn::tls_deserialize_exact(message)?;
        let protocol = incoming
            .try_into_protocol_message()
            .map_err(|_| Error::invalid("that message is not a group message"))?;

        let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
        if !group.is_active() {
            return Err(Error::NotAMember);
        }

        let application = protocol.content_type() == openmls::prelude::ContentType::Application;
        let framed_epoch = protocol.epoch().as_u64();
        let copy_epoch = group.epoch().as_u64();
        let processed = match group.process_message(&self.provider, protocol) {
            Ok(processed) => processed,
            // The device's own store, not the message: a retry may work.
            Err(ProcessMessageError::StorageError(err)) => {
                return Err(Error::Storage(err.to_string()))
            }
            // A SPENT KEY: the message's ratchet key is gone. Said as a
            // duplicate only for an application message, and the message
            // door keeps it one only when its record shows these bytes
            // opened here ([`Self::process_application`]).
            Err(ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError),
            ))) if application => {
                return Err(Error::Duplicate("the key this message needs was spent"))
            }
            // A COPY THAT DID NOT DECRYPT spent its key all the same: OpenMLS
            // takes the key from the ratchet before the AEAD check, and
            // writes the ratchet back only for a message that decrypted. So
            // the store still holds the key, and the group in memory is
            // loaded again from it; otherwise a tampered copy handed over
            // first would leave the real message nothing to open with.
            Err(
                err @ ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::AeadError | MessageDecryptionError::MalformedContent,
                )),
            ) => {
                let reloaded =
                    MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id))
                        .map_err(|err| {
                            Error::Mls(format!("could not reload a stored group: {err}"))
                        })?;
                if let Some(reloaded) = reloaded {
                    self.groups.insert(group_id.to_vec(), reloaded);
                }
                return Err(mls_err(err));
            }
            // FRAMED PAST THIS COPY'S EPOCH: a message or commit from an
            // epoch this copy never reached. The commit that would carry it
            // there came first in the mailbox and did not apply, so the copy
            // is behind or on another branch and will not catch up from what
            // was delivered. Said as its own error, so a client knows to read
            // the group's head and hand it to the recovery driver
            // ([`crate::recovery`]), which says whether to rejoin. The
            // framing is anyone's to write who holds the group id, so this
            // alone never rejoins. A commit framed BELOW the copy (a
            // duplicate, a replay) stays [`Error::Mls`].
            Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch))
                if framed_epoch > copy_epoch =>
            {
                return Err(Error::StaleCopy {
                    message_epoch: framed_epoch,
                    copy_epoch,
                })
            }
            Err(err) => return Err(mls_err(err)),
        };
        // From here on the message opened and its signature held: whatever is
        // refused below was sent by a device that held a leaf at the
        // message's epoch ([`Self::commit_strands`] asks).
        self.last_refusal_authenticated = true;
        // An application message's words go into a [`Secret`] at once, so
        // every refusal below drops them wiped.
        let sender = processed.sender().clone();
        let credential = processed.credential().clone();
        let message_epoch = processed.epoch();
        let content = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                Ok(crate::secret::Secret::new(application.into_bytes()))
            }
            other => Err(other),
        };
        // An application message that opened is remembered, so its bytes
        // handed over again read as a duplicate
        // ([`Self::process_application`]). A refusal below takes the note
        // back with the key ([`Self::process_whole`]): the message is then
        // refused again, as it was the first time. An own message's echo is
        // not one that opened.
        if content.is_ok() {
            self.provider
                .peachy_storage()
                .note_opened(group_id, &crate::storage::opened_digest(message))?;
        }

        // Our own message, fanned back by the delivery service. Checked before
        // anything else looks at the sender: an own PrivateMessage is not
        // decryptable by its author and its signature is not verifiable, so
        // asking who sent it would be asking a question with no answer.
        if matches!(
            content,
            Err(ProcessedMessageContent::OwnPendingCommit
                | ProcessedMessageContent::OwnPrivateMessage)
        ) {
            // A SAVED COMMIT'S ECHO (§A commit saved across a restart): the
            // delivery service hands a commit on only once it took it, and
            // these are the very bytes that were staged (an own
            // `PrivateMessage` cannot be opened by its author, so the bytes
            // are what tells it from another commit of this device's). That
            // is the verdict the earlier run never heard, so it is merged. A
            // stage of this run's own is merged by the call that submitted
            // it, on the answer; its echo stays only an echo.
            if self.is_saved_commit_echo(group_id, message)? {
                log::warn!("peachy-mls: a saved commit came back taken — merging it");
                self.merge_pending_commit(group_id)?;
            }
            return Ok(Incoming::Echo);
        }

        let sender_kind = SenderKind::from(&sender);
        let sender_leaf = match &sender {
            openmls::prelude::Sender::Member(index) => Some(*index),
            _ => None,
        };
        // The sender gate runs before the content is looked at, so an external
        // join is refused as an external join rather than as whatever its
        // payload happened to be.
        self.rules
            .evaluate_commit_sender(sender_kind)
            .into_result()?;

        // WHO the sender is: every check on its credential but the expiry,
        // which each arm below judges for itself, at its own instant. An
        // application message is judged on this reader's wall, and on a
        // signed revocation this reader holds
        // ([`crate::identity::judge_message_sender`]), because no state forks
        // on whether one member read a message; a commit is judged on the
        // group's tree clock, because a member's state does
        // (docs/identity.md §A received commit is judged on the tree
        // clock).
        let (sender_identity, _wall_lapsed) = {
            // A MESSAGE FROM AN EPOCH THE GROUP HAS LEFT was verified by
            // OpenMLS against that epoch's tree, so the leaf index it names
            // belongs to that tree, not to this one: the seat may be empty
            // now, or somebody else's. The sender is judged by its device key
            // instead, which its credential binds and which every member
            // checked against its leaf when it was seated. A device with no
            // leaf in the tree NOW was removed after that epoch, and it still
            // holds the epoch's keys, so what it seals there is refused
            // without a word: [`Error::NotFromAMember`].
            let signature_key = if message_epoch == group.epoch() {
                Self::signature_key_of_sender(group, &sender)?
            } else {
                let device_key = PeachyIdentityProvider::claimed_device_key(&credential)
                    .ok_or(CredentialRejection::Malformed)?;
                group
                    .members()
                    .find(|member| member.signature_key.as_slice() == device_key.as_slice())
                    .map(|member| member.signature_key)
                    .ok_or(Error::NotFromAMember(
                        "sealed at an earlier epoch by a device the group has since removed",
                    ))?
            };
            self.identity_provider.validate_seated_credential(
                &credential,
                &signature_key,
                i64::MAX,
            )?
        };
        let revoked_at = if application {
            Self::sender_revoked_at(self.provider.peachy_storage(), &sender_identity)?
        } else {
            None
        };
        // Sealed in the epoch the group is in now: that epoch's tree clock,
        // which its sender cannot move, judges it too
        // (docs/identity.md §A lapsed leaf's new messages). One from an epoch the
        // group has left is judged on its receive time alone.
        let sealed_tree_clock =
            (message_epoch == group.epoch()).then(|| Self::tree_clock(group, None));
        match content {
            Ok(mut words) => {
                match crate::identity::judge_message_sender(
                    sender_identity.expires_at,
                    self.identity_provider.now_unix(),
                    received_at,
                    revoked_at,
                    sealed_tree_clock,
                ) {
                    // Its account signed its key out, and nothing places this
                    // message's receipt before that. Refused as a removed
                    // device's message is, without a word.
                    crate::identity::MessageSenderVerdict::Revoked => {
                        return Err(Error::NotFromAMember(
                            "received from a device after its account signed it out",
                        ));
                    }
                    // Past the grace, or a lapsed sender's new message:
                    // received after its sender lapsed, or sealed where the
                    // tree clock says so. The refusal rolls back like any
                    // other, so nothing is spent.
                    crate::identity::MessageSenderVerdict::Expired => {
                        return Err(CredentialRejection::Expired.into());
                    }
                    crate::identity::MessageSenderVerdict::ReadLapsed => {
                        // The grace's use. Logged, because a device talking
                        // on a lapsed credential is a device that has not
                        // renewed its leaf — one that has been away, or
                        // one that never renews — and that is worth seeing even though
                        // nobody is refused.
                        log::warn!(
                            "peachy-mls: reading a message from a leaf whose credential has \
                             expired — inside the grace, so it is delivered"
                        );
                    }
                    crate::identity::MessageSenderVerdict::Read => {}
                }
                // The other half of a round trip
                // ([`ROUND_TRIP_ROTATION_MIN_SECONDS`]): another person was
                // heard from, so this device's next renewal moment in a
                // two-person group replaces its leaf. Its own other devices
                // do not count.
                if sender_identity.actor_id != self.identity.actor_id {
                    self.provider.peachy_storage().note_peer_heard(group_id)?;
                }
                Ok(Incoming::Application {
                    sender: sender_identity,
                    plaintext: std::mem::take(&mut *words),
                })
            }

            Err(ProcessedMessageContent::ProposalMessage(queued)) => {
                // A standalone proposal from a LAPSED leaf is refused, and
                // "lapsed" is read off the tree clock — the tree plus the leaf
                // an Update would install — never this reader's wall.
                // Whether a proposal is stored decides whether a later commit
                // naming it stages at all, so a verdict that differed between
                // members would be a fork one commit later: the member who
                // refused it could not apply the commit the rest merged.
                //
                // And then the proposal rules refuse it unless it is a
                // LEAVE: a standalone proposal is by reference, and Peachy
                // takes none but a Remove of a leaf of its sender's own person
                // (`crate::rules` §Why proposals by reference are refused). So
                // nothing else reaches the proposal store, and nothing else a
                // member queues can ride into a commit somebody else builds.
                // A leave is stored by every member, the leaver's own other
                // devices included: the commit that carries it names it by
                // reference, and a member without it could not apply that.
                let update_leaf = match queued.proposal() {
                    openmls::prelude::Proposal::Update(update) => Some(update.leaf_node()),
                    _ => None,
                };
                let tree_clock = update_leaf
                    .and_then(|leaf| PeachyIdentityProvider::claimed_issued_at(leaf.credential()))
                    .into_iter()
                    .fold(Self::tree_clock(group, None), i64::max);
                if sender_identity.expires_at <= tree_clock {
                    return Err(CredentialRejection::Expired.into());
                }
                // An Update proposal carries the leaf its sender wants to
                // become, and it is checked the way a commit's update path is.
                if let Some(leaf) = update_leaf {
                    Self::check_renewed_leaf(
                        &self.identity_provider,
                        &sender_identity,
                        leaf,
                        tree_clock,
                    )?;
                }
                let kind = ProposalKind::from(queued.proposal());
                let ctx = Self::proposal_context(&self.identity_provider, group, &queued);
                self.rules.evaluate(&ctx).into_result()?;
                let reference = queued.proposal_reference_ref().as_slice().to_vec();
                let epoch = group.epoch().as_u64();
                group
                    .store_pending_proposal(self.provider.storage(), *queued)
                    .map_err(|err| Error::Mls(err.to_string()))?;
                // THE BYTES IT CAME AS, for the commit that takes it to carry
                // ([`crate::carried_commit`]): a member that never got this
                // proposal could not apply that commit without them. The
                // rules above take no proposal but a leave.
                if kind == ProposalKind::Remove {
                    self.provider
                        .peachy_storage()
                        .note_carried_leave(group_id, epoch, &reference, message)?;
                }
                Ok(Incoming::ProposalQueued {
                    sender: sender_identity,
                    kind,
                })
            }

            // A stranger proposing to add themselves. Refused by policy before
            // it reaches the proposal store, so it can never become part of a
            // commit somebody else builds.
            Err(ProcessedMessageContent::ExternalJoinProposalMessage(_)) => {
                Err(Error::PolicyRefused(DenyReason::ExternalJoin))
            }

            Err(ProcessedMessageContent::StagedCommitMessage(staged)) => {
                // THE NEW LEAF, when the commit carries an update path: the
                // committer's own seat, re-signed. It must be the same seat and
                // carry a credential no older than the one it replaces —
                // docs/identity.md §Refreshing a seated leaf. This runs
                // for every commit, not only a refresh: an add or a remove
                // carries a path too, and a committer must not be able to
                // re-badge its leaf by riding a credential change on some
                // other change.
                //
                // EVERY expiry below is judged at the TREE CLOCK and none on
                // this reader's wall: the sender's grace, the path leaf, a
                // swept-up Update's proposer and leaf, each added key package.
                // On the wall, a member catching up after the sender's exp plus
                // the grace would refuse the commit the rest had merged — the
                // same fork as the one above, fifty-six days further out.
                // First, the ceiling on how far this commit may move the
                // clock everything below is judged on.
                Self::refuse_tree_clock_jump(Self::tree_clock(group, None), &staged)?;
                let tree_clock = Self::tree_clock(group, Some(&staged));
                if tree_clock
                    >= sender_identity
                        .expires_at
                        .saturating_add(crate::identity::EXPIRED_LEAF_GRACE_SECONDS)
                {
                    return Err(CredentialRejection::Expired.into());
                }
                if let Some(leaf) = staged.update_path_leaf_node() {
                    Self::check_renewed_leaf(
                        &self.identity_provider,
                        &sender_identity,
                        leaf,
                        tree_clock,
                    )?;
                }
                // A LAPSED COMMITTER MAY ONLY RENEW, and "lapsed" is read off
                // the TREE CLOCK — never this receiver's wall, which is what
                // forked Bo when he caught up on day 31 with Ada's day-25 add
                // (docs/identity.md §A received commit is judged on the
                // tree clock). `refuse_lapsed_committer` says why the rule has
                // to be enforced here and not only by the committer's client.
                Self::refuse_lapsed_committer(sender_identity.expires_at, tree_clock, &staged)?;
                if sender_identity.expires_at <= tree_clock {
                    log::warn!(
                        "peachy-mls: applying a commit whose sender's credential has expired — \
                         a renewal inside the grace, so it is applied"
                    );
                }
                // The proposal rules, on every proposal the commit carries or
                // names. One named by reference is refused here, whole commit
                // and all: an honest committer never names one.
                let contexts: Vec<ProposalContext> = staged
                    .queued_proposals()
                    .map(|queued| Self::proposal_context(&self.identity_provider, group, queued))
                    .collect();
                if let PolicyDecision::Deny(reason) = self.rules.evaluate_all(contexts.iter()) {
                    return Err(Error::PolicyRefused(reason));
                }

                // By-reference Update proposals in this commit, each renewing
                // ITS sender's leaf. Refused by the rules above; checked
                // anyway, so the identity rule stands on its own.
                for update in staged.update_proposals() {
                    let openmls::prelude::Sender::Member(index) = update.sender() else {
                        return Err(Error::PolicyRefused(DenyReason::UpdateOfAnotherLeaf));
                    };
                    let old = group
                        .members()
                        .find(|member| member.index == *index)
                        .ok_or(Error::NoSuchMember)?;
                    let (proposer, _lapsed) =
                        self.identity_provider.validate_seated_credential_at(
                            &old.credential,
                            &old.signature_key,
                            crate::identity::EXPIRED_LEAF_GRACE_SECONDS,
                            tree_clock,
                        )?;
                    Self::check_renewed_leaf(
                        &self.identity_provider,
                        &proposer,
                        update.update_proposal().leaf_node(),
                        tree_clock,
                    )?;
                }

                // The group's policy, each proposal judged as its own
                // sender's.
                Self::refuse_by_group_policy(
                    &self.identity_provider,
                    group,
                    &staged,
                    sender_leaf.ok_or(Error::PolicyRefused(DenyReason::ExternalSender))?,
                    Self::policy_actor(
                        &sender_identity.actor_id,
                        sender_identity.expires_at,
                        tree_clock,
                    ),
                    tree_clock,
                )?;

                // One person, one account key: no leaf this commit adds may
                // carry a key other than its actor's other leaves carry, or,
                // for this device's own actor, other than this device's own.
                // A device pins no key for its own actor, so this is what
                // keeps a device the server certified under a key of its own
                // out of its person's groups.
                Self::refuse_account_key_conflict(
                    &self.identity_provider,
                    group,
                    &staged,
                    &self.identity,
                )?;

                // THE SIZE CAPS, receiver side, as the committer holds to them.
                if let Some(reason) =
                    Self::commit_size_refusal(&self.identity_provider, group, &staged)
                {
                    return Err(Error::invalid(reason));
                }

                // Every leaf this commit introduces is checked BEFORE the
                // commit is merged. A commit that would add somebody we cannot
                // identify is refused whole; there is no half-merged state.
                //
                // With the grace, at the tree clock (`received_leaf_at`): the
                // committer checked each key package strictly when it built
                // the Add, on its own clock, and a member processing the
                // commit days later must not refuse — and fork on — a package
                // that was live then.
                let mut added = Vec::new();
                for proposal in staged.add_proposals() {
                    added.push(Self::received_leaf_at(
                        &self.identity_provider,
                        proposal.add_proposal().key_package().leaf_node(),
                        tree_clock,
                    )?);
                }
                let removed: Vec<u32> = staged
                    .remove_proposals()
                    .map(|proposal| proposal.remove_proposal().removed().u32())
                    .collect();
                let removed_self = staged.self_removed();
                let left = Self::leavers(&self.identity_provider, group, &staged);
                let removed_actors = Self::actors_at_leaves(
                    &self.identity_provider,
                    &self.identity.actor_id,
                    group,
                    &removed,
                );

                // The keys this account's other devices held in the leaves
                // the commit takes out, read before the merge: a replace that
                // put another key in the same device's seat leaves the new
                // key as the only one in the tree, and the notice input must
                // still know which key that id held before
                // (`Client::own_sibling_leaves`).
                let removed_siblings = Self::own_siblings_at_leaves(
                    &self.identity_provider,
                    &self.identity,
                    group,
                    &removed,
                );
                // ONE DEVICE, ONE LEAF, receiver side, as the adder holds to
                // it (`refuse_if_device_seated`). The refusal rolls back like
                // any other, so nothing is merged.
                if Self::seats_a_second_leaf(&self.identity_provider, group, &removed, &added) {
                    return Err(Error::invalid(
                        "a commit seats a second leaf for a device id that already holds one",
                    ));
                }
                // A RESEAT UNDER ANOTHER DEVICE KEY, in any group, as the
                // adder holds to it (`replace_member`).
                if Self::rekeys_a_removed_seat(&self.identity_provider, group, &removed, &added) {
                    return Err(Error::invalid(
                        "a commit re-seats a device id under another device key",
                    ));
                }

                // A LEAF OF THIS ACCOUNT SEATED BY A COMMITTER THIS DEVICE
                // DOES NOT TRUST (a contact answering a seat ask, say) is no
                // evidence the person let that device in. Judged on the
                // state before the merge, so the commit's own adds vouch for
                // nothing; recorded after it, so a refused merge leaves no
                // trace (`own_devices.rs` §A leaf this device did not see
                // vouched for).
                let mut outside_the_gate = self.seats_outside_the_gate(&sender_identity, &added);
                // A sibling's seat the commit hands to another key is no
                // device of this account's, whoever committed it.
                for pair in Self::rekeyed_own_seats(&removed_siblings, &self.identity, &added) {
                    if !outside_the_gate.contains(&pair) {
                        outside_the_gate.push(pair);
                    }
                }

                // What the commit does to the steward key the group counts,
                // judged on the state before the merge (`StewardMerge`).
                let steward_actor = Self::policy_actor(
                    &sender_identity.actor_id,
                    sender_identity.expires_at,
                    tree_clock,
                )
                .to_owned();
                if let Some(merge) = self.steward_merge_of(group_id, &steward_actor, false)? {
                    self.steward_merges.insert(group_id.to_vec(), merge);
                }

                // The epoch this commit leaves: an envelope a slower sender
                // sealed in it still opens after the merge.
                let added_next = added
                    .iter()
                    .map(|identity| device_key_digest(&identity.device_key))
                    .collect();
                if let Err(err) = self.note_envelope_epoch(group_id, Some(added_next)) {
                    log::warn!("peachy-mls: could not keep the epoch's envelope secret: {err}");
                }
                let group = self.groups.get_mut(group_id).ok_or(Error::NoSuchGroup)?;
                group
                    .merge_staged_commit(&self.provider, *staged)
                    .map_err(mls_err)?;
                let epoch = group.epoch().as_u64();
                // WHO LEFT: a person whose last leaf this commit took out. A
                // later seat ask of theirs is judged against this, not only
                // against the tree (`verify_join_request`).
                for actor in Self::without_a_leaf(&self.identity_provider, group, removed_actors) {
                    self.provider
                        .peachy_storage()
                        .set_departed(group_id, &actor)?;
                }
                // WHO CAME BACK: a person this commit seats again.
                for leaf in &added {
                    self.provider
                        .peachy_storage()
                        .clear_departed(group_id, &leaf.actor_id)?;
                }
                // The commit is merged: a store that cannot take the note
                // must not make it look refused.
                if let Err(err) = self.note_seats_outside_the_gate(&outside_the_gate) {
                    log::warn!("peachy-mls: could not record an untrusted seat: {err}");
                }
                if let Err(err) = self.note_own_sibling_keys(&removed_siblings) {
                    log::warn!("peachy-mls: could not record a sibling's key: {err}");
                }
                // The epoch the copy entered, for a trailing head to be
                // judged against ([`Self::confirm_head`]).
                if let Err(err) = self.note_copy_epoch(group_id) {
                    log::warn!("peachy-mls: could not record the copy's epoch: {err}");
                }

                Ok(Incoming::Commit(CommitOutcome {
                    sender: sender_identity,
                    added,
                    removed,
                    removed_self,
                    left,
                    epoch,
                }))
            }

            // Handled above: an own message's echo before the sender was
            // read, an application message's words taken out as `Ok`.
            // Repeated here because the match must be exhaustive and a `_`
            // arm would silently absorb the next variant OpenMLS adds.
            Err(
                ProcessedMessageContent::OwnPendingCommit
                | ProcessedMessageContent::OwnPrivateMessage
                | ProcessedMessageContent::ApplicationMessage(_),
            ) => Ok(Incoming::Echo),
        }
    }

    // ---- Exporters ----------------------------------------------------------

    /// Derive a secret from the current epoch, RFC 9420 §8.5.
    ///
    /// Sealed typing and the sealed-sender verifier key off it, so neither
    /// ever handles the group's own key material. The label namespaces it — two features exporting under different labels
    /// cannot derive each other's secret.
    pub fn export_secret(
        &self,
        group_id: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        if label.is_empty() {
            return Err(Error::invalid("an exporter label must not be empty"));
        }
        if length == 0 || length > u16::MAX as usize {
            return Err(Error::invalid("an exported secret must be 1..=65535 bytes"));
        }
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if !group.is_active() {
            return Err(Error::NotAMember);
        }
        group
            .export_secret(self.provider.crypto(), label, context, length)
            .map_err(mls_err)
    }

    /// Derive a secret from the epoch this device's STAGED commit would move
    /// the group to, before that commit is merged.
    ///
    /// The one caller is the sessionless commit door
    /// (docs/delivery.md §SubmitCommit): `SubmitCommit` carries the
    /// verifier of the NEXT epoch's send key in the same request as the
    /// commit, so no second, attributable publish follows every commit. The
    /// committer can only know that secret before the Delivery Service has
    /// taken the commit, which is exactly when the commit is staged and not
    /// yet merged. OpenMLS derives it from the staged commit's own epoch
    /// secrets (`StagedCommit::export_secret`), the same derivation
    /// [`Self::export_secret`] runs after the merge, so the two agree.
    ///
    /// `NoPendingCommit`-shaped refusal (`Error::invalid`) when nothing is
    /// staged; `NotAMember` when the staged commit removes this device.
    pub fn export_pending_secret(
        &self,
        group_id: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        if label.is_empty() {
            return Err(Error::invalid("an exporter label must not be empty"));
        }
        if length == 0 || length > u16::MAX as usize {
            return Err(Error::invalid("an exported secret must be 1..=65535 bytes"));
        }
        let group = self.groups.get(group_id).ok_or(Error::NoSuchGroup)?;
        if !group.is_active() {
            return Err(Error::NotAMember);
        }
        let staged = group
            .pending_commit()
            .ok_or_else(|| Error::invalid("there is no staged commit to export from"))?;
        staged
            .export_secret(self.provider.crypto(), label, context, length)
            .map_err(|_| Error::NotAMember)
    }

    // ---- Internals ----------------------------------------------------------

    fn create_config(capabilities: Capabilities) -> MlsGroupCreateConfig {
        Self::create_config_builder(capabilities).build()
    }

    fn create_config_builder(capabilities: Capabilities) -> MlsGroupCreateConfigBuilder {
        MlsGroupCreateConfig::builder()
            .ciphersuite(PEACHY_CIPHERSUITE)
            // Every Peachy leaf advertises `peachy_group_meta`, whether or not
            // its group is ever renamed: OpenMLS refuses a
            // GroupContextExtensions proposal unless EVERY existing member
            // already supports the extension, so a capability that arrived only
            // when it was wanted would arrive one epoch too late for ever.
            // `mls/core/src/group_meta.rs` §Capabilities has the whole of it.
            .capabilities(capabilities)
            .wire_format_policy(PEACHY_WIRE_FORMAT_POLICY)
            // The tree rides in the Welcome. Without it, joining needs an
            // out-of-band ratchet tree from the delivery service, which does
            // not exist yet — and a Welcome that cannot be acted on alone is a
            // join flow with a hidden second request in it.
            .use_ratchet_tree_extension(true)
            .max_past_epochs(RETAINED_PAST_EPOCHS)
            .sender_ratchet_configuration(sender_ratchet())
            .padding_size(APPLICATION_PADDING_BLOCK)
    }

    /// Also what an existing group is upgraded TO in [`Self::encrypt`], so it
    /// must stay the join-side half of [`Self::create_config`] exactly.
    fn join_config() -> MlsGroupJoinConfig {
        Self::join_config_padded_to(APPLICATION_PADDING_BLOCK)
    }

    fn join_config_padded_to(padding: usize) -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            .wire_format_policy(PEACHY_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(RETAINED_PAST_EPOCHS)
            .sender_ratchet_configuration(sender_ratchet())
            .padding_size(padding)
            .build()
    }

    /// The signature key of whoever sent a processed message.
    ///
    /// Only a `Member` sender has a leaf to read it from. Every other sender
    /// kind is refused by policy before this is called, so reaching it with one
    /// is a bug in the ordering rather than a case to handle.
    fn signature_key_of_sender(
        group: &MlsGroup,
        sender: &openmls::prelude::Sender,
    ) -> Result<Vec<u8>> {
        match sender {
            openmls::prelude::Sender::Member(index) => group
                .members()
                .find(|member| member.index == *index)
                .map(|member| member.signature_key)
                .ok_or(Error::NoSuchMember),
            _ => Err(Error::PolicyRefused(DenyReason::ExternalJoin)),
        }
    }

    /// Whether an Update proposal changes its own sender's leaf.
    ///
    /// RFC 9420 gives an Update no target field — it always means the sender's
    /// leaf — so for an Update from a member this is true by construction, and
    /// the check exists for the shapes where it is not: an Update arriving from
    /// a non-member sender, which the policy refuses on the sender alone.
    fn update_targets_sender(queued: &openmls::prelude::QueuedProposal) -> bool {
        matches!(queued.sender(), openmls::prelude::Sender::Member(_))
    }
}

#[cfg(test)]
mod rejoin_report_tests {
    use super::RejoinReport;

    fn readded(by: &str, device: &str, untrusted: bool) -> RejoinReport {
        RejoinReport {
            readded_by: by.into(),
            readded_by_device: device.into(),
            readded_by_untrusted: untrusted,
            ..RejoinReport::default()
        }
    }

    /// A fold names the untrusted re-adder, whichever report held it: the
    /// device the flag exists to name is never swapped for a trusted one's.
    #[test]
    fn a_fold_keeps_the_untrusted_re_adder() {
        let mut folded = readded("actor-ada", "device-x", true);
        folded.fold(readded("actor-alice", "device-alice", false));
        assert_eq!(folded, readded("actor-ada", "device-x", true));

        let mut folded = readded("actor-alice", "device-alice", false);
        folded.fold(readded("actor-ada", "device-x", true));
        assert_eq!(folded, readded("actor-ada", "device-x", true));

        let mut folded = readded("actor-alice", "device-alice", false);
        folded.fold(readded("actor-bo", "device-bo", false));
        assert_eq!(folded, readded("actor-bo", "device-bo", false));
    }
}
