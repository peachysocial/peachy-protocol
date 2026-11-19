// SPDX-License-Identifier: MIT
//! Persistent group state: one `StorageProvider` over a four-verb key-value
//! host interface.
//!
//! docs/mls-core.md §Storage layout is the map of what lands where. This module
//! header is the argument for the shape.
//!
//! ## Why a KV interface and not four StorageProviders
//!
//! OpenMLS reaches storage through
//! [`openmls_traits::storage::StorageProvider`], a trait with 53 methods, each
//! generic over the entity type it moves. Implementing it once per platform
//! would be four chances to key an entity differently, and a device that keyed
//! `EpochKeyPairs` one way on iOS and another on Android would be a device that
//! reads its own state back empty after a restore. So the trait is implemented
//! **once**, here, in Rust, and everything platform-specific collapses into
//! four verbs:
//!
//! ```text
//! get(key)            -> Option<bytes>
//! put(key, value)
//! delete(key)
//! scan(prefix)        -> [(key, value)]
//! flush()             durability point; see below
//! ```
//!
//! Bytes in, bytes out. A backend never parses a value and never invents a key:
//! [`storage_key`] builds every one of them, so the layout is a property of
//! this file rather than of whichever platform happened to write the row.
//!
//! ## The version byte
//!
//! Every key starts with [`STORAGE_SCHEMA_VERSION`]. The stamp is also written
//! once, under the `meta` namespace, and [`PeachyStorage::open`] refuses a
//! store written by a future version rather than reading it with today's rules
//! — the same argument `CredentialRejection::UnsupportedVersion` makes about a
//! credential from a future format. A schema change is then a bump and a
//! migration, not a silent reinterpretation of bytes already on a phone.
//!
//! ## Durability, and the window
//!
//! OpenMLS writes a group operation as MANY independent `put`s and offers the
//! provider no transaction hook — no begin, no commit, not even a "that was the
//! last one". A backend that made every `put` durable on its own would still be
//! interruptible halfway through a commit, so per-`put` durability buys
//! nothing that matters and costs an fsync per row.
//!
//! So durability is a separate verb. [`KvStore::flush`] is the point at which
//! everything written since the last one becomes visible to the next process,
//! and [`Client`](crate::Client) calls it at the end of every operation that
//! changes state. A backend is free to buffer until then — the SQLite one holds
//! a deferred transaction, the wasm one holds a dirty set it hands to
//! IndexedDB — which makes the whole of one MLS operation land or none of it.
//!
//! **The window is real and it is this:** a crash between an operation
//! returning and its `flush` completing loses that operation. What it does NOT
//! do is leave half of it behind, which is the failure that would matter: a
//! group whose tree advanced but whose epoch secrets did not is a group that
//! can never read another message, and no amount of re-fetching repairs it.
//! Losing the last operation is recoverable by construction: a client
//! acknowledges an envelope only after the call that applied it has
//! returned and its flush is durable (SQLite in `synchronous = FULL`; a wasm
//! host's own flush, docs/mls-core.md §wasm binding), so the
//! delivery service still holds the commit of any operation a crash lost
//! (docs/delivery.md §Retention), and the device applies it again.
//!
//! ## A step that fails part-way
//!
//! The same holds when the operation is not killed but FAILS part-way: a
//! write refused for a full disk, a read that hits an I/O error, a stored
//! value that does not decode. OpenMLS stops at that step and returns an
//! error, with every write before it already in the transaction. So
//! [`PeachyStorage`] marks the transaction failed at the first refused step,
//! refuses every later write in it, and its flush then ROLLS BACK instead of
//! committing ([`KvStore::rollback`]); dropping the store does the same. No
//! path commits a transaction that lost a step: not a later flush, not the
//! C ABI's commit after the call, not a drop. [`Client`](crate::Client)
//! then loads its groups again from what the store holds, so the retry
//! starts from the last whole operation (`Client::synced`).
//!
//! ## What is NOT here
//!
//! Encryption at rest. The bytes handed to a backend are group secrets in the
//! clear; the backend protects them. The SQLite one is SQLCipher, keyed by the
//! caller (`mls/core/src/sqlite.rs` §Encryption at rest), on a backup-excluded
//! file; the browser's IndexedDB has only its origin's isolation; `MemoryKv`
//! never leaves the process.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use openmls_rust_crypto::RustCrypto;
use openmls_traits::storage::{traits, Entity, StorageProvider, CURRENT_VERSION};
use openmls_traits::OpenMlsProvider;

use crate::secret::Secret;

/// The version byte every key in this store starts with.
///
/// Bump it when the meaning of a namespace changes, never when one is added:
/// an added namespace is invisible to an older reader, which is the whole point
/// of a per-key prefix rather than one global schema row.
pub const STORAGE_SCHEMA_VERSION: u8 = 1;

/// Separates the namespace from the entity key. ASCII unit separator.
///
/// Unambiguous by construction: every entity key downstream of it is
/// `serde_json` output, and JSON escapes every control byte, so 0x1F cannot
/// occur inside one. A `scan` for a namespace therefore cannot spill into the
/// namespace whose name it happens to be a prefix of.
const NAMESPACE_SEPARATOR: u8 = 0x1f;

// ---- Namespaces -------------------------------------------------------------
//
// One per OpenMLS entity kind, plus two of Peachy's own. The strings are the
// on-disk layout: renaming one is a schema change and needs the version byte
// bumped, which is why they are spelled out here rather than derived from a
// Rust type name that a refactor would quietly follow.

/// Peachy's own: the schema stamp, and anything else about the store itself.
const NS_META: &[u8] = b"meta";
/// Peachy's own: the group ids this device holds state for. The key is the raw
/// group id and the VALUE is the same bytes, so a scan hands back the ids
/// without parsing anything — see [`PeachyStorage::remembered_group_ids`].
const NS_GROUP_INDEX: &[u8] = b"group";
const NS_JOIN_CONFIG: &[u8] = b"join_config";
const NS_OWN_LEAF_NODES: &[u8] = b"own_leaf_nodes";
const NS_QUEUED_PROPOSAL: &[u8] = b"queued_proposal";
const NS_PROPOSAL_REFS: &[u8] = b"proposal_refs";
const NS_TREE: &[u8] = b"tree";
const NS_INTERIM_TRANSCRIPT_HASH: &[u8] = b"interim_transcript_hash";
const NS_GROUP_CONTEXT: &[u8] = b"group_context";
const NS_CONFIRMATION_TAG: &[u8] = b"confirmation_tag";
const NS_GROUP_STATE: &[u8] = b"group_state";
const NS_MESSAGE_SECRETS: &[u8] = b"message_secrets";
const NS_RESUMPTION_PSK: &[u8] = b"resumption_psk";
const NS_OWN_LEAF_INDEX: &[u8] = b"own_leaf_index";
const NS_EPOCH_SECRETS: &[u8] = b"epoch_secrets";
const NS_SIGNATURE_KEY: &[u8] = b"signature_key";
const NS_ENCRYPTION_KEY: &[u8] = b"encryption_key";
const NS_EPOCH_KEY_PAIRS: &[u8] = b"epoch_key_pairs";
const NS_KEY_PACKAGE: &[u8] = b"key_package";
const NS_PSK: &[u8] = b"psk";
/// Peachy's own: the account identity key this device last accepted as each
/// actor's current one, keyed by `actor_id`
/// ([`crate::group::Client::observe_account_keys`]).
const NS_ACCOUNT_PIN: &[u8] = b"account_pin";
/// Peachy's own: the account identity key each group last showed as each
/// actor's current one, keyed by a length-prefixed group id then the
/// `actor_id`, so every conversation a changed key is seen in says so once.
const NS_ACCOUNT_SEEN: &[u8] = b"account_seen";
/// Peachy's own: the account identity keys this device has seen each actor
/// move away from (a pin replaced by a new key), keyed by `actor_id`; a
/// reseat never seats the person under one of them again
/// ([`crate::group::Client::reseat_person`]).
const NS_ACCOUNT_RETIRED: &[u8] = b"account_retired";
/// Peachy's own: the signed `iat` of the leaf that made each actor's current
/// pin current, keyed by `actor_id`; a leaf under a key they moved away from
/// issued no later than this predates the move
/// ([`crate::group::Client::observe_account_keys`]).
const NS_ACCOUNT_PIN_SINCE: &[u8] = b"account_pin_since";
/// Peachy's own: the leaves (`account_leaf_digest` in crate::group, which
/// binds the leaf's keys to its credential) a group's conversation has
/// settled for the account-key notice while their key was the person's
/// current one, keyed by group id. Absent for a conversation this core has
/// not read. Kept when the copy is forgotten for a rejoin; dropped when
/// the group is left for good ([`PeachyStorage::forget_account_leaf_records`]).
const NS_ACCOUNT_KNOWN_LEAVES: &[u8] = b"account_known_leaves_v2";
/// Peachy's own: the leaves a group's conversation has REPORTED, or accepted
/// in silence at a first sight, under a key that is not the person's current
/// one, keyed by group id. A leaf under a key the person moved away from is
/// settled only when it is here: one settled while its key was current is
/// said once when the key is retired. No leaf is in both records after a
/// read: a read first drops each report of a leaf the known record holds,
/// and last drops from the known record each leaf it reported. Absent until
/// this core has read the conversation. Kept and dropped with
/// [`NS_ACCOUNT_KNOWN_LEAVES`].
const NS_ACCOUNT_REPORTED_LEAVES: &[u8] = b"account_reported_leaves_v2";
/// The two records above in their version-1 layout, by a digest of the
/// leaf's keys alone. Read once, at open, carried into the records above
/// for the leaves each held tree still holds, and deleted
/// ([`PeachyStorage::account_leaf_records_v1`]).
const NS_ACCOUNT_KNOWN_LEAVES_V1: &[u8] = b"account_known_leaves";
/// See [`NS_ACCOUNT_KNOWN_LEAVES_V1`].
const NS_ACCOUNT_REPORTED_LEAVES_V1: &[u8] = b"account_reported_leaves";
/// Peachy's own: the account keys each person's pin moved to or off while a
/// group's copy was forgotten for a rejoin, keyed by a length-prefixed group
/// id then the `actor_id` (the [`NS_ACCOUNT_SEEN`] layout), 32 bytes each,
/// sorted. A forgotten copy has no tree to read a leaf's key from, so the
/// pin-move prune records the keys here, and the copy's next read drops its
/// reports of that person's leaves under them, then this record. Dropped
/// with [`NS_ACCOUNT_KNOWN_LEAVES`] too.
const NS_ACCOUNT_MOVED_WHILE_FORGOTTEN: &[u8] = b"account_moved_while_forgotten";
/// Peachy's own: written once, key `done`, value `1`, when this device has
/// dated every pin with no time recorded from every
/// conversation it holds at once (`redate_undated_pins` in crate::group),
/// before any notice is judged.
const NS_ACCOUNT_PINS_DATED: &[u8] = b"account_pins_dated";
/// Peachy's own: when this device last put a fresh leaf of its own into each
/// group, and how many frames it has sealed there since, keyed by group id
/// ([`crate::group::Client::leaf_rotation_due`]). 16 bytes: the Unix second,
/// then the count, both big-endian.
const NS_LEAF_ROTATION: &[u8] = b"leaf_rotation";
/// Peachy's own: that this device has opened an application message from
/// another person in each group since it last put a fresh leaf of its own
/// there, keyed by group id, valued with the one byte `1`
/// ([`crate::group::Client::leaf_rotation_due`], the round-trip rotation of a
/// two-person group).
const NS_PEER_HEARD: &[u8] = b"peer_heard";
/// Peachy's own: the counter of this device's call participations, under the
/// one key `seq`, valued with the last one it handed out (8 bytes,
/// big-endian) ([`crate::group::Client::next_call_participation_seq`]). It
/// only rises; a participation's `Joined` and `MediaKey` carry it, and it
/// orders one device's participations however its wall clock moves.
const NS_CALL_PARTICIPATION: &[u8] = b"call_participation";
/// Peachy's own: every LAST-RESORT key package this device still holds the
/// private half of, keyed by its raw KeyPackageRef, valued with the Unix second
/// it was minted (8 bytes, big-endian)
/// ([`crate::group::Client::generate_last_resort_key_package_with_ref`]).
/// OpenMLS never deletes a package carrying the `last_resort` extension on
/// use, so without this index nothing would ever delete one at all.
const NS_LAST_RESORT: &[u8] = b"last_resort";
/// Peachy's own: the actor whose commit seated this device in each group by
/// a Welcome (the Welcome's GroupInfo signer), keyed by group id, valued with
/// the UTF-8 actor id ([`crate::group::Client::welcome_sender`]). Absent for a
/// group this device founded, or joined on a build before it was kept.
const NS_WELCOME_SENDER: &[u8] = b"welcome_sender";
/// Peachy's own: the SHA-256 of the commit message this device staged in each
/// group, keyed by group id, from the stage to its merge or clear
/// ([`crate::group::Client::settle_saved_commit`]). A commit's echo is a
/// `PrivateMessage` its author cannot open, so it is told apart from any
/// other commit of this device's by these bytes alone.
const NS_STAGED_COMMIT: &[u8] = b"staged_commit";
/// Peachy's own: every signed seat ask this device has taken in, keyed by the
/// SHA-256 of its group id, its 16-byte nonce and its 64-byte signature,
/// valued with its signed `issued_at` (8 bytes, big-endian)
/// ([`crate::group::Client::first_sight_of_join_request`]). Pruned once an
/// ask is too old to verify anyway.
const NS_JOIN_REQUEST_SEEN: &[u8] = b"join_request_seen";
/// Peachy's own: the device of this account that let THIS device in, as the
/// device learned it while taking the account key (the box opened under that
/// device's key), keyed by its device id, valued with its raw 32-byte signing
/// key ([`crate::group::Client::remember_own_approver`]). One of the keys
/// [`crate::group::Client::check_own_device_approval`] trusts.
const NS_OWN_APPROVER: &[u8] = b"own_approver";
/// Peachy's own: the link between an install's two device rows, as this
/// device first saw the account's device list state it, keyed by the linked
/// row's device id, valued with the id of the row it names as `twin_of`
/// ([`crate::group::Client::note_own_install_links`]). First sight wins; a
/// signed revocation reaches a linked row only through its pinned link
/// (`crate::revocation`, §Which keys a device signs).
const NS_OWN_INSTALL_LINK: &[u8] = b"own_install_link";
/// Peachy's own: the keys a PIN restore signs out, as the registration that
/// restored answered them ([`crate::group::Client::note_restore_signed_out`]),
/// keyed by the restore's `restored_since` (8 bytes, big-endian), valued with
/// a JSON array of the keys in the rows' hex form. First write wins, and an
/// approval this device signs writes an empty one when none is kept yet
/// ([`crate::group::Client::sign_own_device_approval`]); a key not in it is
/// never signed for that restore, and none is signed before one is kept
/// (`crate::revocation`, §A PIN restore signs the others).
const NS_RESTORE_SNAPSHOT: &[u8] = b"restore_snapshot";
/// Peachy's own: every device key this device signed the account's
/// revocation of, or took from a restore's answer as signed out, keyed by the
/// 32-byte key, valued with nothing. This device never approves one of them
/// again ([`crate::group::Client::sign_own_device_approval`]).
const NS_OWN_KEY_SIGNED_OUT: &[u8] = b"own_key_signed_out";
/// Peachy's own: the account's signed revocation of a device key, for any
/// person's device, keyed by the 32-byte device key, valued with the 64-byte
/// signature followed by a big-endian i64: the second the delivery service
/// said the revocation took effect, `0` when it did not say. Written only
/// once the signature verified under the account identity key of a leaf
/// that carries the key ([`crate::group::Client::stale_leaf_removable`]),
/// and checked again against each message's sender before it refuses one
/// ([`crate::identity::judge_message_sender`]). A revocation is permanent, so
/// nothing removes an entry.
const NS_PEER_REVOKED: &[u8] = b"peer_revoked";
/// Peachy's own: the roster of a group this device forgot, keyed by group id,
/// valued with a JSON array of `{"a": actor_id, "k": [32 bytes]?}`
/// ([`crate::group::Client::forget_group`]). Kept until a copy in the id is
/// confirmed, so a Welcome back is drawn against the people this device knew
/// (who was added, who is gone). Each
/// person this device sees leave afterwards is dropped from it
/// ([`PeachyStorage::set_departed`]); nobody is added.
const NS_REMEMBERED_ROSTER: &[u8] = b"remembered_roster";
/// Peachy's own: what each Welcome that restored or replaced a group this
/// device knew brought with it (or what a head said against the copy held),
/// keyed by group id, valued with a JSON list of
/// [`crate::group::RejoinReport`] (`[{"by": actor_id, "d": device_id?,
/// "u": true?, "added": [actor_id, ...], "left": [actor_id, ...]?,
/// "adm": true?, "c": true?}, ...]`), oldest first, each kept until the
/// client takes it ([`crate::group::Client::take_rejoin_report`]).
const NS_REJOIN_REPORT: &[u8] = b"rejoin_report";
/// Peachy's own: the people whose last leaf this device saw leave each group,
/// keyed by a length-prefixed group id then the `actor_id` (the
/// [`NS_ACCOUNT_SEEN`] layout), valued with one byte, `1`. Written when a
/// commit this device applies removes an actor's last leaf, and when a Welcome
/// that restores or replaces a group this device knew leaves out somebody of
/// the roster it knew; writing it drops the person from
/// [`NS_REMEMBERED_ROSTER`]. Cleared for each person a commit this device
/// merges adds, and for every actor holding a leaf in the copy it holds once
/// it takes a seat and before it keeps that copy's roster: a person seated
/// again is no longer departed.
/// Kept when the group is forgotten, so a device that rejoins still knows
/// who left; dropped by [`crate::group::Client::forget_remembered_roster`].
/// Read by [`crate::group::Client::verify_join_request`]: a caller's
/// `pending_actors` never re-seats one of these people.
const NS_DEPARTED: &[u8] = b"departed";
/// Peachy's own: devices of this device's own account that the account
/// removed and this device has forgotten, keyed by device id, valued `[1]`
/// ([`crate::group::Client::forget_own_device`]). Kept for good: a removed
/// device's id never comes back.
const NS_OWN_FORGOTTEN: &[u8] = b"own_forgotten";
/// Peachy's own: leaves of this device's own account that a commit seated
/// while its committer was no device this device trusts, keyed by the
/// leaf's raw 32-byte device key then its device id, valued `[1]`
/// ([`crate::group::Client::own_device_anchors`]). Dropped when an approval
/// this device can check vouches for the same device and key.
const NS_OWN_UNVOUCHED: &[u8] = b"own_unvouched";
/// Peachy's own: the device key this device holds for each of its own
/// account's OTHER devices, keyed by device id
/// ([`crate::group::Client::own_sibling_leaves`]). Valued with the raw
/// 32-byte key when it was taken from a tree (a leaf this device did not see
/// seated from outside the gate), or with the key then
/// [`SIBLING_KEY_EVIDENCE`] when it was taken from evidence (an approval
/// that verified, or this device's own add). Evidence replaces a key taken
/// from a tree; nothing else is ever overwritten: a later leaf under the same
/// id and another key is another device wearing that id, and the new-device
/// notice is told so. Kept for good, like [`NS_OWN_FORGOTTEN`].
const NS_OWN_SIBLING_KEY: &[u8] = b"own_sibling_key";
/// The byte after the key in an [`NS_OWN_SIBLING_KEY`] record taken from
/// evidence.
const SIBLING_KEY_EVIDENCE: u8 = 1;
/// Peachy's own: every device key this device has seen a FORGOTTEN device of
/// its own account hold ([`NS_OWN_FORGOTTEN`]), keyed by the raw 32-byte key,
/// valued with the device id it was seen under
/// ([`crate::group::Client::forget_own_device_with_key`]). A forgotten key
/// counts for nothing under any id, for good: a removed device's key that the
/// server lists again under a fresh id is the same removed device.
const NS_OWN_FORGOTTEN_KEY: &[u8] = b"own_forgotten_key";
/// Peachy's own: the `(device_id, device_key)` pairs of this account's own
/// devices that [`crate::group::Client::check_own_device_approval`] answered
/// with a verdict that seats, keyed by the raw 32-byte key then the device
/// id, valued `[1]`. This device's own add of a sibling is evidence only for
/// such a pair (or one it already trusted); any other own add is recorded
/// unvouched.
const NS_OWN_SEAT_VOUCHED: &[u8] = b"own_seat_vouched";
/// Peachy's own: the `(device_id, device_key)` pairs of this account's own
/// devices that this device holds on the approval chain
/// ([`crate::group::Client::own_device_anchors`]): an approval it verified
/// under a device already on the chain. Keyed by the raw 32-byte key then the
/// device id, valued with the raw 32-byte keys of the devices whose approvals
/// for it verified here, one after another (`[1]` in a record written before
/// approvers were kept). Never taken from a tree or a watched seat. Kept for
/// good; a forgotten id or key counts for nothing whatever this records, and
/// a pair stays on the chain only while one of its approvers does
/// ([`crate::group::Client::own_device_anchors`]).
const NS_OWN_VOUCHED: &[u8] = b"own_vouched";
/// One [`NS_OWN_VOUCHED`] record: the `(device_id, device_key)` pair, and the
/// keys of the devices that vouched for it (`None` for a record written
/// before approvers were kept).
pub type OwnVouched = ((String, Vec<u8>), Option<Vec<Vec<u8>>>);
/// Residue only: a store can hold the OWN account's devices of a group
/// this device forgot here, keyed by group id. Nothing reads or writes it (a kept roster names this device's own person, which is what made
/// such a group one this device knew); [`PeachyStorage::forget_remembered_roster`]
/// still deletes such a record.
const NS_REMEMBERED_OWN_DEVICES: &[u8] = b"remembered_own_devices";
/// Peachy's own: the highest epoch the group's head vouched for on this
/// device, keyed by group id, valued with a big-endian u64. Raised to the
/// epoch of a seat taken against the head
/// ([`crate::group::Client::join_from_welcome_at_head`]), to the epoch a held
/// copy is confirmed at ([`NS_HEAD_CONFIRMED`]), and, before a confirmed copy
/// stops being confirmed or is deleted or replaced, to the epoch it reached.
/// Never lowered and never dropped, by a removal, a leave, a forget or any
/// head. A Welcome at or below it is refused: a group only moves forward on
/// this device. A seat taken below the head raises it to the seat's own
/// epoch, below the head's; the epochs an unconfirmed copy reaches after
/// that raise nothing, so nobody can raise it past the real group's head by
/// handing this device a group of their own under the id. A record that is not 8 bytes reads as
/// the highest epoch there is: unreadable refuses every Welcome into the id.
const NS_EPOCH_MARK: &[u8] = b"epoch_mark";
/// Peachy's own: every Welcome this device took through a LAST-RESORT key
/// package, valued with the raw KeyPackageRef of the package it opened, and
/// keyed by what the Welcome opened to ([`welcome_taken_key`]): the group, the
/// epoch and the transcript the joiner's signed GroupInfo names. Taking that
/// seat a second time is refused, however the Welcome around it was
/// re-encoded. Records a store holds keyed by the SHA-256 of the whole
/// Welcome are read too. Dropped with the package's private half, when
/// nothing can open that Welcome any more.
const NS_WELCOME_TAKEN: &[u8] = b"welcome_taken";
/// Peachy's own: what the group's head said of the copy of a group held now,
/// keyed by group id, valued with one byte ([`HeadState`]): `1` CONFIRMED,
/// the copy matched the head (seen at one of its epochs under the head's
/// verifier by [`crate::group::Client::confirm_head`], this device's own
/// commit merged, a seat taken at the head, or a group this device founded);
/// `2` LAPSED, it matched once and a head at its epoch named another send key
/// since; `0` UNCONFIRMED, a seat taken below the head (or with none) that no
/// head has matched yet, and CONTESTED, the same byte with a
/// [`NS_COPY_CONTESTED`] record beside it. No record: a copy held before this
/// record was kept (made LAPSED at the next open), or none held. Every other
/// value reads as confirmed, the state that counts the most toward the epoch
/// mark and trusts nothing new. Dropped when the copy is deleted.
const NS_HEAD_CONFIRMED: &[u8] = b"head_confirmed";
/// Peachy's own: one byte, `1`, keyed by group id: the unconfirmed copy held
/// now is CONTESTED, the delivery service contradicted it (a head naming an
/// epoch the copy held under another send key, or the head given at its join
/// not matching the copy once it got there). Kept apart from
/// [`NS_HEAD_CONFIRMED`], which stays `0`, so a build that predates it reads
/// the copy as unconfirmed, which vouches for nothing, rather than reading an
/// unknown byte as confirmed. Dropped with any other head state, or when the
/// copy is deleted.
const NS_COPY_CONTESTED: &[u8] = b"copy_contested";
/// Peachy's own: the head given when the copy of a group held now was seated
/// below it, keyed by group id, valued with its epoch (8 bytes, big-endian)
/// then its 32-byte verifier. The delivery service's word at the join, held
/// against the copy's own send key once the copy reaches that epoch
/// ([`NS_HEAD_CONFIRMED`]). Dropped when the copy is confirmed or deleted.
const NS_JOIN_HEAD: &[u8] = b"join_head";
/// Peachy's own: the verifier (SHA-256 of the send key) the copy of a group
/// held now had at each of its last [`COPY_VERIFIERS_KEPT`] epochs, keyed by
/// group id, valued with records of the epoch (8 bytes, big-endian) then the
/// 32-byte verifier, oldest first. What a head that trails an unconfirmed
/// copy is checked against ([`crate::group::Client::confirm_head`]). Dropped
/// when the copy is deleted.
const NS_COPY_VERIFIERS: &[u8] = b"copy_verifiers";
/// Peachy's own: how many commits of this device's own the delivery service
/// refused in a row in the copy of a group held now, keyed by group id,
/// valued with a big-endian u32. Reset when one of its commits merges;
/// dropped when the copy is deleted.
const NS_OWN_COMMITS_REFUSED: &[u8] = b"own_commits_refused";
/// Peachy's own: the group state (the raw `peachy_group_meta` JSON: `adm`,
/// `pol`, `dm`, `lk`, `ban` and the rest) of a group this device forgot,
/// kept beside [`NS_REMEMBERED_ROSTER`] under the same condition and keyed by
/// the same group id. What a Welcome back into the id is drawn against for
/// whether the admins changed ([`crate::group::Client::forget_group`]).
const NS_REMEMBERED_POLICY: &[u8] = b"remembered_policy";
/// Peachy's own: the roster of a copy this device forgot when no head had
/// ever matched it (an unconfirmed or contested copy), keyed by group id,
/// valued like [`NS_REMEMBERED_ROSTER`]. Read, with it, to draw a Welcome
/// back into the id against.
const NS_REMEMBERED_UNVOUCHED: &[u8] = b"remembered_unvouched";
/// Peachy's own: the devices of a copy this device forgot or replaced, keyed
/// by group id, valued with a JSON array of `[actor_id, device_id]` pairs,
/// this device itself never among them ([`crate::group::Client::forget_group`]).
/// Kept and dropped with [`NS_REMEMBERED_ROSTER`]; read only to report the
/// devices a Welcome back leaves out of people it keeps
/// ([`crate::group::RejoinReport::dropped_devices`]).
const NS_REMEMBERED_DEVICES: &[u8] = b"remembered_devices";
/// Peachy's own: the first millisecond the next rejoin report of a group may
/// be drawn at, keyed by group id, valued with 8 bytes big-endian
/// ([`crate::group::Client::peek_rejoin_report`]). Each report drawn owns the
/// milliseconds from its time to this, one for each line it can draw, so
/// no two reports of a group ever share a line's time. Kept for the life of
/// the store, through a forget: a report drawn after a rejoin still never
/// lands on a line drawn before it.
const NS_REJOIN_DRAW_FLOOR: &[u8] = b"rejoin_draw_floor";
/// Peachy's own: the groups this device is LEAVING, keyed by group id,
/// valued with the epoch it last proposed its person's removal at (8 bytes,
/// big-endian) ([`crate::group::Client::begin_leave`]). The group's state is
/// kept, read by nothing but the leave, until a commit removes this device
/// or the leave is given up; then the group and this record are forgotten.
const NS_LEAVING: &[u8] = b"leaving";
/// Peachy's own: each LEAVE this device took in through the message door,
/// as the bytes it arrived as, keyed by a length-prefixed group id then the
/// proposal's raw reference (the [`NS_ACCOUNT_SEEN`] layout), valued with
/// the epoch it was taken at (8 bytes, big-endian) and then the message. A
/// commit of the leave carries these bytes ([`crate::carried_commit`]).
/// Those of other epochs are dropped whenever one is written, and all of a
/// group's when it is forgotten.
const NS_CARRIED_LEAVE: &[u8] = b"carried_leave";
/// Peachy's own: each application message this device opened, so a copy
/// handed over again reads as a duplicate rather than a loss
/// ([`crate::Error::Duplicate`]). Keyed by a length-prefixed group id (the
/// [`NS_ACCOUNT_SEEN`] layout) then the first 16 bytes of the SHA-256 of the
/// message as it arrived ([`opened_digest`]); valued with the record's
/// sequence number in that group (8 bytes, big-endian). At most
/// [`OPENED_KEPT`] per group are kept, the oldest dropped first; all of a
/// group's go when it is forgotten.
const NS_OPENED: &[u8] = b"opened";
/// Peachy's own: the count beside [`NS_OPENED`], keyed by the raw group id: 16
/// bytes, the next sequence number then the lowest one still kept, both
/// big-endian u64.
const NS_OPENED_COUNT: &[u8] = b"opened_count";

/// How many opened messages [`NS_OPENED`] remembers per group. A replay of
/// one older than this does not read as a duplicate: it fails to open as a
/// message that came too late does.
pub const OPENED_KEPT: u64 = 4096;
/// How far past [`OPENED_KEPT`] a group's record may grow before the oldest
/// are dropped, so the scan that drops them runs once per this many opens
/// rather than on every one.
const OPENED_PRUNE_SLACK: u64 = 512;

/// The key of an [`NS_OPENED_CONTENT`] record: the envelope id, a zero
/// byte, then the digest; with no digest, the prefix every record under the
/// id shares. Callers refuse an id holding a zero byte.
fn opened_content_key(id: &str, digest: Option<&[u8; 16]>) -> Vec<u8> {
    let mut key = Vec::with_capacity(id.len() + 17);
    key.extend_from_slice(id.as_bytes());
    key.push(0);
    if let Some(digest) = digest {
        key.extend_from_slice(digest);
    }
    storage_key(NS_OPENED_CONTENT, &key)
}

/// The digest an [`NS_OPENED`] record keys a message by: the first 16 bytes of
/// the SHA-256 of the MLS message exactly as it arrived.
pub(crate) fn opened_digest(message: &[u8]) -> [u8; 16] {
    use sha2::Digest;
    let full: [u8; 32] = sha2::Sha256::digest(message).into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Peachy's own: the envelope secret
/// (`MLS-Exporter("peachy envelope epoch v1", group id, 32)`) the copy of a
/// group held now had at each of its last epochs, keyed by group id, valued
/// with records of the epoch (8 bytes, big-endian), one byte (`1` when every
/// leaf of that epoch said it reads envelopes keyed by the epoch, else `0`),
/// the 32-byte secret, then the leaves the commit that left the epoch
/// added: a count byte ([`ADDED_UNKNOWN`] when not recorded) and that many
/// SHA-256 digests of their device keys. Oldest first. What opens a version
/// 3 envelope sealed at an epoch the copy has since left, what seals a commit
/// under the epoch it was built in ([`crate::group::Client::seal_envelope`]),
/// and what tells which of these epochs a device handed its seat back held
/// ([`crate::group::Client::replace_member`]). As many epochs as the group
/// keeps message secrets for, and the current one. Dropped when the copy is
/// deleted or replaced.
const NS_ENVELOPE_EPOCHS: &[u8] = b"envelope_epochs";

/// The count byte of an [`NS_ENVELOPE_EPOCHS`] record whose commit's adds
/// were not recorded (or were too many to list): read as "every leaf may be
/// new here".
const ADDED_UNKNOWN: u8 = 0xFF;

/// Peachy's own: the envelope secrets of the epochs this device's seat was
/// held while its copy could not follow, handed back in the Welcome that
/// returned the seat to it (`crate::welcome_frame` §The gap block), keyed by
/// group id, valued with records of the epoch (8 bytes, big-endian) and the
/// 32-byte secret. What opens an envelope sealed to this device while it was
/// behind or forked. Replaced by the next such Welcome; dropped with the
/// group.
const NS_ENVELOPE_GAP: &[u8] = b"envelope_gap";

/// Peachy's own: version 3 envelopes this device was sent that opened for no
/// group it holds, kept so the ones sealed while its copy was behind or forked
/// open once a Welcome hands it the epochs it missed
/// ([`crate::group::Client::hold_envelope`]). One key, valued with records of
/// the mailbox kind (1 byte), the time the server received it (milliseconds,
/// 8 bytes big-endian), the envelope id (2-byte length, UTF-8) and the
/// envelope (4-byte length), oldest first.
const NS_HELD_ENVELOPES: &[u8] = b"held_envelopes";
/// Peachy's own: version 3 envelopes held on a DEVICE SEAL
/// ([`crate::device_seal`], [`crate::group::Client::hold_envelope_sealed`]),
/// one record per envelope, keyed by the SHA-256 of the envelope's bytes, so
/// the same envelope handed over under a thousand mailbox ids is held once.
/// Valued with a [`SealedHold`] ([`SealedHold::encode`]); the envelope's
/// bytes are kept apart, under [`NS_HELD_BODY`], so a pass reads every
/// entry's record and no envelope.
const NS_HELD_SEALED: &[u8] = b"held_sealed";
/// The bytes of each envelope held in [`NS_HELD_SEALED`], under the same key.
/// Written and deleted in the same write as its record.
const NS_HELD_BODY: &[u8] = b"held_body";
/// Peachy's own: the SHA-256 of each envelope held on its device seal and
/// released ([`crate::group::Client::release_held`]), valued with when
/// (milliseconds, 8 bytes big-endian): the same bytes delivered again are not
/// held again. A seal dropped, or refused as not its message's author's, is
/// no release. Those older than 30 days, and the oldest past
/// [`HELD_RELEASED_KEPT`], go at a client's first pass and hourly after it.
const NS_HELD_RELEASED: &[u8] = b"held_released";
/// The most [`NS_HELD_RELEASED`] records kept; the oldest go first.
pub(crate) const HELD_RELEASED_KEPT: usize = 4096;
/// Peachy's own: WHO EACH DEVICE KEY BELONGED TO in a group this device held,
/// keyed by group id, so a device seal from a device that has since left the
/// tree still names its person ([`crate::group::Client::next_reopenable`]).
/// Valued with a version byte ([`LEAF_PEOPLE_VERSION`]), when the copy was
/// let go (milliseconds, 8 bytes big-endian; `0` while it is held), then
/// records of the device key (32), the epoch at
/// which the copy first held no leaf with it (8 bytes big-endian; `0` while
/// it holds one), when this device saw that, by its own clock (milliseconds,
/// 8 bytes big-endian; `0` while it holds one) and the actor id (1-byte
/// length, UTF-8). Every key is taken from a leaf whose credential checked.
/// Filled at every epoch the copy enters, at most [`LEAF_PEOPLE_KEPT`] keys,
/// the longest gone first; a group let go more than 30 days ago is dropped
/// at a client's first pass, and hourly after it.
const NS_LEAF_PEOPLE: &[u8] = b"leaf_people";
/// The most keys [`NS_LEAF_PEOPLE`] keeps per group.
pub(crate) const LEAF_PEOPLE_KEPT: usize = 2048;
/// The first byte of every [`NS_LEAF_PEOPLE`] value; a record of any other
/// version does not read.
const LEAF_PEOPLE_VERSION: u8 = 1;

/// Peachy's own: what an application message opened to, kept IN THE WRITE
/// THAT SPENT ITS KEY until the client says its own copy is stored
/// ([`crate::group::Client::process_message_as`],
/// [`crate::group::Client::release_opened`]). Keyed by the UTF-8 mailbox
/// envelope id, a zero byte, and the message's 16-byte [`opened_digest`], so
/// a second message handed over under one id is kept beside the first, never
/// over it; valued with a version byte (`1`), when it was kept
/// (milliseconds, 8 bytes big-endian), the group id (2-byte length), the
/// 16-byte [`opened_digest`] of the message, the sender (actor id and device
/// id, 2-byte lengths; the 32-byte device key; kid, 2-byte length; expiry and
/// issue seconds, 8 bytes big-endian each; one byte `1` and the 32-byte
/// account key, or `0`), then the plaintext. Those older than 30 days, and
/// the oldest past [`OPENED_CONTENT_KEPT`], go at a client's first keep or
/// release and then hourly ([`crate::group::OPENED_PRUNE_EVERY_MS`]).
const NS_OPENED_CONTENT: &[u8] = b"opened_content";

/// The most [`NS_OPENED_CONTENT`] records kept; the oldest go first.
pub const OPENED_CONTENT_KEPT: usize = 1000;

/// One record of [`NS_OPENED_CONTENT`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpenedContent {
    pub(crate) kept_at_ms: u64,
    pub(crate) group_id: Vec<u8>,
    pub(crate) digest: [u8; 16],
    pub(crate) sender: crate::identity::PeachyIdentity,
    pub(crate) plaintext: Secret<Vec<u8>>,
}

impl OpenedContent {
    fn encode(&self) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        fn short(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
            out.extend_from_slice(&u16::try_from(bytes.len()).ok()?.to_be_bytes());
            out.extend_from_slice(bytes);
            Some(())
        }
        // The whole record's length before the first push, so the plaintext
        // is never left behind by a reallocation; wiped when dropped.
        let mut out = zeroize::Zeroizing::new(Vec::with_capacity(
            160 + self.group_id.len()
                + self.sender.actor_id.len()
                + self.sender.device_id.len()
                + self.sender.kid.len()
                + self.plaintext.len(),
        ));
        out.push(1);
        out.extend_from_slice(&self.kept_at_ms.to_be_bytes());
        short(&mut out, &self.group_id)?;
        out.extend_from_slice(&self.digest);
        short(&mut out, self.sender.actor_id.as_bytes())?;
        short(&mut out, self.sender.device_id.as_bytes())?;
        out.extend_from_slice(&self.sender.device_key);
        short(&mut out, self.sender.kid.as_bytes())?;
        out.extend_from_slice(&self.sender.expires_at.to_be_bytes());
        out.extend_from_slice(&self.sender.issued_at.to_be_bytes());
        match &self.sender.account_key {
            Some(key) => {
                out.push(1);
                out.extend_from_slice(key);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.plaintext);
        Some(out)
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        fn take<'a>(rest: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            let (head, tail) = rest.split_at_checked(n)?;
            *rest = tail;
            Some(head)
        }
        fn short<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
            let len = take(rest, 2)?;
            take(rest, usize::from(u16::from_be_bytes([len[0], len[1]])))
        }
        fn text(rest: &mut &[u8]) -> Option<String> {
            String::from_utf8(short(rest)?.to_vec()).ok()
        }
        fn be8(rest: &mut &[u8]) -> Option<[u8; 8]> {
            take(rest, 8)?.try_into().ok()
        }
        let mut rest = raw;
        if take(&mut rest, 1)? != [1] {
            return None;
        }
        let kept_at_ms = u64::from_be_bytes(be8(&mut rest)?);
        let group_id = short(&mut rest)?.to_vec();
        let digest: [u8; 16] = take(&mut rest, 16)?.try_into().ok()?;
        let actor_id = text(&mut rest)?;
        let device_id = text(&mut rest)?;
        let device_key: [u8; 32] = take(&mut rest, 32)?.try_into().ok()?;
        let kid = text(&mut rest)?;
        let expires_at = i64::from_be_bytes(be8(&mut rest)?);
        let issued_at = i64::from_be_bytes(be8(&mut rest)?);
        let account_key = match take(&mut rest, 1)? {
            [0] => None,
            [1] => Some(take(&mut rest, 32)?.try_into().ok()?),
            _ => return None,
        };
        Some(Self {
            kept_at_ms,
            group_id,
            digest,
            sender: crate::identity::PeachyIdentity {
                actor_id,
                device_id,
                device_key,
                kid,
                expires_at,
                issued_at,
                account_key,
            },
            plaintext: Secret::new(rest.to_vec()),
        })
    }
}

/// One epoch's record in [`NS_ENVELOPE_EPOCHS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvelopeEpochRecord {
    pub(crate) epoch: u64,
    /// Every leaf of that epoch said it reads envelopes keyed by the epoch.
    pub(crate) all_read_it: bool,
    pub(crate) secret: Secret<[u8; 32]>,
    /// SHA-256 digests of the device keys of the leaves the commit leaving
    /// this epoch added; `None` when not recorded.
    pub(crate) added_next: Option<Vec<[u8; 32]>>,
}

/// How pressed a [`SealedHold`] is to be handed out
/// ([`crate::group::Client::next_reopenable`]). Only ever raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum HoldDue {
    /// Waits for this device's copy of its group to pass its epoch.
    Waiting = 0,
    /// Past the byte budget or 30 days old: handed out once its group's copy
    /// is no longer merely behind it, or at once if no copy is held.
    Due = 1,
    /// Near the hold's ceiling: handed out at the next pass, whatever its
    /// copy's epoch.
    Urgent = 2,
}

/// An epoch envelope secret a held envelope's seal carried, on the heap and
/// wiped when dropped. On the heap so that a [`SealedHold`] or a grant holding
/// it moves by its pointer: a hold is pushed, sorted, collected and kept in a
/// map, and a secret held inline would be copied by every one of those moves
/// into a block freed unwiped (the scratch of a sort, a vector's old block, a
/// map's old table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldSecret(Box<Secret<[u8; 32]>>);

impl std::ops::Deref for HeldSecret {
    type Target = [u8; 32];

    fn deref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `bytes` as a [`HeldSecret`].
pub(crate) fn held_secret(bytes: &[u8; 32]) -> HeldSecret {
    HeldSecret(Box::new(Secret::new(*bytes)))
}

/// One envelope held on its device seal ([`NS_HELD_SEALED`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SealedHold {
    /// The SHA-256 of the envelope: the record's key.
    pub(crate) digest: [u8; 32],
    /// The mailbox kind it came under.
    pub(crate) mailbox_kind: u8,
    /// When the server received it, in milliseconds since the epoch.
    pub(crate) received_at_ms: u64,
    /// The envelope's length, for the hold's byte budget.
    pub(crate) bytes: u32,
    /// The epoch the message inside was sealed in, read off its header.
    pub(crate) epoch: u64,
    /// How pressed it is to be handed out.
    pub(crate) due: HoldDue,
    /// Handed out at least once, so the words it opened to may be kept
    /// ([`NS_OPENED_CONTENT`]) from a run that died before releasing it.
    pub(crate) handed: bool,
    /// The epoch envelope secret the seal carried.
    pub(crate) secret: HeldSecret,
    /// The sender's device key.
    pub(crate) sender_key: [u8; 32],
    /// The group the seal named (at most 64 bytes).
    pub(crate) group_id: Vec<u8>,
    /// The mailbox id it was first held under.
    pub(crate) id: String,
}

impl SealedHold {
    const VERSION: u8 = 1;

    /// Version (1), mailbox kind (1), received (8), length (4), epoch (8),
    /// due (1), handed (1), secret (32), sender key (32), group id (1-byte
    /// length), then the mailbox id (UTF-8, the rest). Integers big-endian.
    fn encode(&self) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        let group_len = u8::try_from(self.group_id.len()).ok()?;
        // Sized past the whole record before the first push, so the secret
        // is never left behind by a reallocation; wiped when dropped.
        let mut out = zeroize::Zeroizing::new(Vec::with_capacity(
            121 + self.group_id.len() + self.id.len(),
        ));
        out.push(Self::VERSION);
        out.push(self.mailbox_kind);
        out.extend_from_slice(&self.received_at_ms.to_be_bytes());
        out.extend_from_slice(&self.bytes.to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.push(self.due as u8);
        out.push(u8::from(self.handed));
        out.extend_from_slice(&self.secret[..]);
        out.extend_from_slice(&self.sender_key);
        out.push(group_len);
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(self.id.as_bytes());
        Some(out)
    }

    fn decode(digest: [u8; 32], raw: &[u8]) -> Option<Self> {
        let (head, rest) = raw.split_at_checked(88)?;
        if head[0] != Self::VERSION {
            return None;
        }
        let due = match head[22] {
            0 => HoldDue::Waiting,
            1 => HoldDue::Due,
            2 => HoldDue::Urgent,
            _ => return None,
        };
        let (group_len, rest) = rest.split_first()?;
        let (group_id, id) = rest.split_at_checked(usize::from(*group_len))?;
        if group_id.is_empty() {
            return None;
        }
        Some(Self {
            digest,
            mailbox_kind: head[1],
            received_at_ms: u64::from_be_bytes(head[2..10].try_into().ok()?),
            bytes: u32::from_be_bytes(head[10..14].try_into().ok()?),
            epoch: u64::from_be_bytes(head[14..22].try_into().ok()?),
            due,
            handed: head[23] == 1,
            secret: held_secret(head[24..56].try_into().ok()?),
            sender_key: head[56..88].try_into().ok()?,
            group_id: group_id.to_vec(),
            id: String::from_utf8(id.to_vec()).ok()?,
        })
    }
}

/// One device key of [`NS_LEAF_PEOPLE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeafPerson {
    /// The device key a leaf of the group held.
    pub(crate) key: [u8; 32],
    /// The first epoch the copy held no leaf with it; `0` while it holds one.
    pub(crate) left_epoch: u64,
    /// When this device saw that, by its own clock (milliseconds); `0` while
    /// the copy holds a leaf with it.
    pub(crate) left_at_ms: u64,
    /// The actor id its credential named.
    pub(crate) actor_id: String,
}

/// What [`NS_LEAF_PEOPLE`] keeps for one group.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LeafPeople {
    /// When the copy was let go; `0` while it is held.
    pub(crate) forgotten_at_ms: u64,
    /// Its keys, in the order they were first seen.
    pub(crate) people: Vec<LeafPerson>,
}

impl LeafPeople {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.people.len() * 72);
        out.push(LEAF_PEOPLE_VERSION);
        out.extend_from_slice(&self.forgotten_at_ms.to_be_bytes());
        for person in &self.people {
            let Ok(actor_len) = u8::try_from(person.actor_id.len()) else {
                continue;
            };
            out.extend_from_slice(&person.key);
            out.extend_from_slice(&person.left_epoch.to_be_bytes());
            out.extend_from_slice(&person.left_at_ms.to_be_bytes());
            out.push(actor_len);
            out.extend_from_slice(person.actor_id.as_bytes());
        }
        out
    }

    /// A record that does not read, or of another version, is none; a key
    /// record that does not read ends the list.
    fn decode(raw: &[u8]) -> Option<Self> {
        let (&version, raw) = raw.split_first()?;
        if version != LEAF_PEOPLE_VERSION {
            return None;
        }
        let (at, mut rest) = raw.split_at_checked(8)?;
        let mut people = Vec::new();
        while let Some((head, tail)) = rest.split_at_checked(49) {
            let Some((actor, tail)) = tail.split_at_checked(usize::from(head[48])) else {
                break;
            };
            let (Ok(actor_id), Ok(key), Ok(left), Ok(left_at)) = (
                String::from_utf8(actor.to_vec()),
                <[u8; 32]>::try_from(&head[..32]),
                <[u8; 8]>::try_from(&head[32..40]),
                <[u8; 8]>::try_from(&head[40..48]),
            ) else {
                break;
            };
            people.push(LeafPerson {
                key,
                left_epoch: u64::from_be_bytes(left),
                left_at_ms: u64::from_be_bytes(left_at),
                actor_id,
            });
            rest = tail;
        }
        Some(Self {
            forgotten_at_ms: u64::from_be_bytes(at.try_into().ok()?),
            people,
        })
    }

    /// What is noted of `key`: its person, and when it left (a `left_epoch`
    /// of `0`: it is a leaf still, as of the last epoch the copy entered).
    pub(crate) fn person_of(&self, key: &[u8]) -> Option<&LeafPerson> {
        self.people
            .iter()
            .find(|person| person.key.as_slice() == key)
    }

    /// Set any time a key left, or the copy was let go, that is ahead of
    /// `now` (noted by a clock that ran ahead and was set back) to `now`, so
    /// its 30 days are not stretched by however far the clock ran; whether
    /// any was.
    pub(crate) fn clamp_left_at(&mut self, now: u64) -> bool {
        let mut clamped = false;
        if self.forgotten_at_ms > now {
            self.forgotten_at_ms = now.max(1);
            clamped = true;
        }
        for person in &mut self.people {
            if person.left_at_ms > now {
                person.left_at_ms = now.max(1);
                clamped = true;
            }
        }
        clamped
    }

    /// Whether `actor_id` holds a leaf of the copy, as of the last epoch it
    /// entered.
    pub(crate) fn seated(&self, actor_id: &str) -> bool {
        self.people
            .iter()
            .any(|person| person.left_epoch == 0 && person.actor_id == actor_id)
    }
}

/// One envelope in [`NS_HELD_ENVELOPES`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldEnvelope {
    /// The mailbox kind it came under (`MailboxKind` on the wire).
    pub mailbox_kind: u8,
    /// When the server received it, in milliseconds since the epoch.
    pub received_at_ms: u64,
    /// The mailbox envelope id.
    pub id: String,
    /// The envelope's bytes.
    pub envelope: Vec<u8>,
}
/// Peachy's own: the steward key a group's meta named at each epoch the
/// copy entered ([`crate::steward`]), for judging a veto of a commit this
/// device merged. Per group: entries of `BE64(epoch) ‖ BE64(unix seconds
/// written) ‖ key (32)`, oldest first; those older than
/// [`crate::steward::STEWARD_KEY_KEPT_SECONDS`], or past the last
/// [`COPY_VERIFIERS_KEPT`] epochs and the one before them, go whenever one
/// is written.
/// Nothing is written for a group whose meta names no key.
const NS_STEWARD_KEYS: &[u8] = b"steward_keys";
/// Peachy's own: the group's hold ([`crate::steward::GroupHold`]), as JSON.
/// Kept after it lapses, until the copy leaves its epoch and another hold
/// replaces it, so a group is held at most once an epoch.
const NS_GROUP_HOLD: &[u8] = b"group_hold";
/// Peachy's own: the steward key the server's sealed stamp named on the last
/// commit this device merged in the group (32 bytes; absent for none). A
/// group counts as ENROLLED only while its meta's `stw.k` is this key
/// ([`crate::steward`]): any member can write `stw`, only the server's
/// steward-key rules move this.
const NS_STAMP_STEWARD: &[u8] = b"stamp_steward";
/// Peachy's own: what the sealed stamps of the commits the copy of a group
/// held now merged said of a steward, since its seat (one byte): 0, every
/// one opened named none; 1, at least one named a key. Absent: the copy has
/// opened no stamp since its seat, so it knows nothing either way. Only a
/// 0 lets [`crate::group::Client::head_rolled_back`] read a head below every
/// epoch the copy keeps as a rollback; a value that does not read counts
/// as 1. Dropped with the copy's records.
const NS_STAMPS_OPENED: &[u8] = b"stamps_opened";
/// Peachy's own: the steward key the group COUNTS for enrollment, kept only
/// while its meta's `stw.k` says otherwise because a commit by somebody who
/// may not change it (`crate::steward::may_change_steward_key`) rewrote it:
/// the key as it stood before (32 bytes), or empty for none. Absent, the
/// meta's `stw.k` counts. A commit that may change it drops the record.
const NS_COUNTED_STEWARD: &[u8] = b"counted_steward";
/// Peachy's own: when this device last finished reading the group's head
/// (BE64 unix milliseconds), which opening the conversation reads to decide
/// whether its head is read again (docs/delivery.md §A commit the
/// server refuses). It belongs to the copy: dropped with the copy's records
/// when a rejoin replaces it, and with the group's index entry
/// ([`PeachyStorage::forget_group`]).
const NS_HEAD_READ: &[u8] = b"head_read";
/// Peachy's own: when the group's last hold began (BE64 unix seconds). NOT
/// dropped with the copy's records, unlike [`NS_GROUP_HOLD`]: a hold record
/// gone while this stays means the copy was forgotten since that hold, and
/// [`crate::steward::HOLD_REPEAT_SECONDS`] reads it. Dropped, with
/// [`NS_HOLD_REPEATS`] and [`NS_HOLD_REJOINED`], when the person leaves the
/// group for good ([`PeachyStorage::forget_hold_history`]).
const NS_HOLD_STARTED: &[u8] = b"hold_started";
/// Peachy's own: how many REPEAT holds of a group began since the full hold
/// [`NS_HOLD_STARTED`] records ([`crate::steward::repeat_hold_cap`]), keyed by
/// group id, valued with a big-endian u32. Kept, as that start is, when the
/// copy is forgotten; reset by the next full hold.
const NS_HOLD_REPEATS: &[u8] = b"hold_repeats";
/// Peachy's own: present (one byte, 1) once a copy of the group was
/// forgotten while a hold was on record, since the full hold
/// [`NS_HOLD_STARTED`] records: the hold ended in a rejoin. Kept, as that
/// start is, when the copy is forgotten, and when a later repeat hold
/// settles by a merge, so a settled repeat does not make the next stall a
/// full hold again inside the day; dropped by the next full hold.
const NS_HOLD_REJOINED: &[u8] = b"hold_rejoined";
/// Peachy's own: the highest epoch of the copy held now that the group's
/// OWN head vouched for (BE64): a head read under the group's handle that
/// named the copy's own verifier at that epoch, a Welcome seated at such a
/// head, or a merge of this device's own commit, which the delivery service
/// took under that handle. A commit some other handle took (anybody can
/// open one under a verifier of their choosing and have a commit placed for
/// the group's members) vouches for nothing. What
/// [`crate::group::Client::head_rolled_back`] holds a head below the copy
/// to. Dropped when the copy is deleted.
const NS_HEAD_VOUCHED: &[u8] = b"head_vouched";

/// How many epochs' verifiers [`NS_COPY_VERIFIERS`] keeps per group.
pub(crate) const COPY_VERIFIERS_KEPT: usize = 64;

/// What the group's head said of a held copy ([`NS_HEAD_CONFIRMED`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeadState {
    /// No record: held from before the record was kept (or not held).
    Unrecorded,
    /// A seat taken below the head, or with none, that no head matched yet.
    Unconfirmed,
    /// Matched the head, and nothing has said otherwise since.
    Confirmed,
    /// Matched the head once; a head at its epoch named another send key.
    Lapsed,
    /// Unconfirmed, and the delivery service contradicted the copy's own
    /// history: still vouches for nothing, and reported.
    Contested,
}

/// The key [`NS_WELCOME_TAKEN`] records a seat under: SHA-256 of a fixed
/// label, the group id with its length, the epoch, and the confirmed
/// transcript hash, all as the verified GroupInfo of the Welcome gives them.
/// Nothing in it is a part of the Welcome the delivery service can change
/// without the Welcome failing to open (its `secrets` list is not signed,
/// and an earlier key over the whole Welcome followed it).
pub(crate) fn welcome_taken_key(group_id: &[u8], epoch: u64, transcript_hash: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut digest = sha2::Sha256::new();
    digest.update(b"peachy welcome taken v2");
    digest.update((group_id.len() as u64).to_be_bytes());
    digest.update(group_id);
    digest.update(epoch.to_be_bytes());
    digest.update((transcript_hash.len() as u64).to_be_bytes());
    digest.update(transcript_hash);
    digest.finalize().to_vec()
}

/// The key under [`NS_META`] holding the schema stamp.
const META_SCHEMA: &[u8] = b"schema";

/// The key a store's schema stamp lives under.
///
/// Public for the same reason [`storage_key`] is: a backend that wants to know
/// whether it can read a store *before* downloading it — the wasm binding, which
/// hydrates a whole store into memory at open — has to ask for this exact key,
/// and a second spelling of it is a second layout.
pub fn schema_stamp_key() -> Vec<u8> {
    storage_key(NS_META, META_SCHEMA)
}

/// Read a store's schema stamp and say whether this build owes it a stamp.
///
/// - `Ok(true)` — the caller owes the store a [`STORAGE_SCHEMA_VERSION`] stamp
///   before writing anything else. Either there is no stamp at all (the store
///   is new, or is one this code has never written to) or the stamp names an
///   OLDER version.
/// - `Ok(false)` — stamped at exactly the version this build writes; nothing to
///   do.
/// - `Err` — stamped NEWER than this build. Refusing is the point: a build that
///   read a newer layout as if it were this one would hand OpenMLS
///   plausible-looking nonsense for a ratchet secret.
///
/// **Only a NEWER stamp is refused**, which is the asymmetry the whole
/// version-byte-first layout exists for (docs/mls-core.md §Storage layout). An
/// older store cannot be misread, because every key it holds sits under its own
/// version byte: this build scanning [`schema_prefix`] sees none of it, so the
/// worst an old store can do is look empty. Refusing it instead would brick a
/// device on the release that bumped the version, for a store the new code is
/// structurally incapable of misinterpreting.
///
/// Re-stamping (rather than leaving the old stamp in place) is what keeps the
/// stamp meaning "the newest schema that has written here". A store left
/// stamped 1 while this build fills it with version-2 rows is the shape that
/// makes a *future* migration lose data: version 3 would read the stamp, decide
/// it had a version-1 store, and migrate rows that were not there. The day
/// there really are two versions, the migration hangs here — it reads the old
/// stamp, moves what it owns, deletes every row left under the old version's
/// prefix in the same transaction (an old secret left on disk would break
/// docs/mls-core.md §Security considerations), and only then lets
/// `open` re-stamp.
pub fn check_schema_stamp(stamp: Option<&[u8]>) -> Result<bool, KvError> {
    match stamp {
        None => Ok(true),
        Some(bytes) => match bytes.first().copied() {
            Some(version) if version == STORAGE_SCHEMA_VERSION => Ok(false),
            Some(version) if version < STORAGE_SCHEMA_VERSION => Ok(true),
            Some(version) => Err(KvError::new(format!(
                "this MLS store is schema version {version}; this build reads {STORAGE_SCHEMA_VERSION}"
            ))),
            None => Err(KvError::new(
                "this MLS store's schema stamp is empty; refusing to guess",
            )),
        },
    }
}

/// Build a storage key: version byte, namespace, separator, entity key.
///
/// Public because the wasm binding's JS-side backend and the node tests read
/// the same layout, and a second implementation of this three-line function is
/// a second layout waiting to diverge.
pub fn storage_key(namespace: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + namespace.len() + key.len());
    out.push(STORAGE_SCHEMA_VERSION);
    out.extend_from_slice(namespace);
    out.push(NAMESPACE_SEPARATOR);
    out.extend_from_slice(key);
    out
}

/// The prefix every key in a namespace shares, for [`KvStore::scan`].
pub fn namespace_prefix(namespace: &[u8]) -> Vec<u8> {
    storage_key(namespace, b"")
}

/// The prefix every key this schema version writes shares.
///
/// What a backend hydrates from at open: one scan, everything this store owns,
/// nothing from a future schema version.
pub fn schema_prefix() -> Vec<u8> {
    vec![STORAGE_SCHEMA_VERSION]
}

// ---- The host interface -----------------------------------------------------

/// Anything a key-value backend can go wrong with.
///
/// One variant on purpose. A caller cannot do anything different for "the disk
/// is full" than for "the database is locked" — both mean this device's MLS
/// state did not persist — and a taxonomy here would be four platforms each
/// guessing which of our variants their own error is.
#[derive(Debug, thiserror::Error)]
#[error("mls storage: {message}")]
pub struct KvError {
    pub message: String,
}

impl KvError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl From<serde_json::Error> for KvError {
    fn from(err: serde_json::Error) -> Self {
        // Counted: a value that would not encode or decode stops the
        // operation part-way exactly as a refused write does (§A step that
        // fails part-way). The conversion runs on the thread doing the
        // operation, and `Client::synced` compares this thread's count around
        // the one door it runs, so the count needs no owner.
        CODEC_FAULTS.with(|count| count.set(count.get().wrapping_add(1)));
        // The text and not the position: a serde error over group secrets
        // would otherwise quote the bytes it choked on.
        Self::new(format!("could not serialise a stored value: {err}"))
    }
}

thread_local! {
    /// How many stored values this thread failed to encode or decode, ever.
    /// Only ever compared with itself across one operation on one thread.
    static CODEC_FAULTS: Cell<u64> = const { Cell::new(0) };
}

/// One row out of [`PeachyStorage`]'s own scans: the key, and its value
/// wiped when it drops.
type WipedEntry = (Vec<u8>, zeroize::Zeroizing<Vec<u8>>);

/// One row out of a [`KvStore::scan`]: the whole key, and its value.
///
/// The whole key and not the part after the prefix, because a caller that
/// scanned a namespace and then wants to delete a row needs the key it would
/// pass to [`KvStore::delete`], and reconstructing it from a suffix is the sort
/// of arithmetic that goes wrong once.
pub type KvEntry = (Vec<u8>, Vec<u8>);

/// The four verbs a platform supplies, plus a durability point.
///
/// `&self` throughout, because [`StorageProvider`] is `&self` throughout;
/// backends own their interior mutability. `Send + Sync` because
/// `mls/core/tests/thread.rs` holds [`Client`](crate::Client) to `Send`, and a
/// backend behind an `Rc` would take that away from every wrapper at once.
pub trait KvStore: Send + Sync + std::fmt::Debug {
    /// The value at `key`, or `None` if there is none. Never an error for
    /// absence — absence is an answer.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError>;

    /// Write `value` at `key`, replacing whatever was there.
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError>;

    /// Remove `key`. Removing a key that is not there is success, not an error.
    fn delete(&self, key: &[u8]) -> Result<(), KvError>;

    /// Every entry whose key starts with `prefix`, in key order.
    ///
    /// Ordered because the one caller that depends on ordering —
    /// [`PeachyStorage::remembered_group_ids`] — wants a client's groups to
    /// load in the same order on every device, so that a bug reproduces rather
    /// than hides behind a hash seed.
    fn scan(&self, prefix: &[u8]) -> Result<Vec<KvEntry>, KvError>;

    /// Make everything written since the last flush durable.
    ///
    /// The default is a no-op, which is correct for a backend whose `put` is
    /// already durable and for one that is purely in memory. See the module
    /// header for what the window between an operation and its flush costs.
    fn flush(&self) -> Result<(), KvError> {
        Ok(())
    }

    /// Discard everything written since the last flush, so the store reads
    /// as it did at that flush.
    ///
    /// What [`PeachyStorage`] calls instead of [`Self::flush`] when a step of
    /// the operation failed part-way (module docs, §A step that fails
    /// part-way). It must also release whatever [`Self::begin_write`] took.
    ///
    /// The default REFUSES: a backend that cannot undo a write cannot keep
    /// the promise that an operation lands whole or not at all, and saying so
    /// is better than a rollback that silently kept half. All three of this
    /// crate's backends implement it.
    fn rollback(&self) -> Result<(), KvError> {
        Err(KvError::new(
            "this store cannot roll back, so an operation that failed part-way may be kept in part",
        ))
    }

    /// Remove from the medium what flushed operations replaced or deleted:
    /// old epoch secrets, spent ratchet keys, a consumed key package's private
    /// half.
    ///
    /// Returns whether the backend now holds nothing superseded. `Ok(false)`
    /// means it could not finish now (another connection was busy) and will
    /// try again at its next flush; it is not an error, and the caller's
    /// operation, already flushed, stands.
    ///
    /// The default is `Ok(true)`, which is correct for a backend that keeps
    /// only current values: an in-memory map, or a host store that overwrites
    /// in place. A backend with an append-only log under it, such as SQLite's
    /// WAL, overrides it (`mls/core/src/sqlite.rs`, §Erasing what an
    /// operation replaced).
    fn erase_superseded(&self) -> Result<bool, KvError> {
        Ok(true)
    }

    /// Take the store's write lock now, for an operation that is about to
    /// read state it will write back, and hold it until the next
    /// [`Self::flush`].
    ///
    /// What makes "read the stored state, then write it back" one step on a
    /// store another process can write: between this call and the flush no
    /// other connection commits, so [`Self::foreign_generation`] asked after
    /// it is still true when the operation writes (docs/mls-core.md
    /// §A store two processes share).
    ///
    /// The default is a no-op, which is correct for a backend only this
    /// process writes.
    fn begin_write(&self) -> Result<(), KvError> {
        Ok(())
    }

    /// [`Self::begin_write`], without waiting for another connection's
    /// lock: false, with nothing taken, when one holds it. For a write that
    /// can as well wait for a later open (the erase of a signing key kept
    /// beside the seed), so a process that shares the store is never held up by it.
    ///
    /// The default takes the lock as [`Self::begin_write`] does.
    fn try_begin_write(&self) -> Result<bool, KvError> {
        self.begin_write().map(|()| true)
    }

    /// A value that changes whenever ANOTHER writer has committed to this
    /// store since this connection last looked, and does not change for this
    /// connection's own commits. `None` when the backend cannot tell, which is
    /// correct only for a store no other process or connection writes while
    /// this one is open.
    ///
    /// [`Client`](crate::Client) compares it, under [`Self::begin_write`],
    /// against the value it saw when it last loaded its groups, and loads them
    /// again from the store when it differs, before it acts. The SQLite
    /// backend answers SQLite's own `data_version`.
    fn foreign_generation(&self) -> Result<Option<u64>, KvError> {
        Ok(None)
    }
}

// ---- The in-memory backend --------------------------------------------------

/// A pure-Rust KV that lives in this process.
///
/// The ephemeral path — tests, a call link's client (its call's group lives
/// in memory: [`PeachyStorage::in_memory`]), and anything that explicitly
/// wants state to die with the process. `Clone` shares the map rather than
/// copying it, which is what makes "drop the client and reopen from the same
/// store" expressible without a file (`mls/core/tests/persistence.rs`).
///
/// Its values are what the core stores: epoch secrets, key-pair private
/// halves, the words an opened message was kept as. Every copy it holds, in
/// the map and in what a rollback would put back, is wiped when it is
/// replaced, deleted, let go by a flush or dropped with the store; and its
/// `Debug` prints counts only.
#[derive(Clone, Default)]
pub struct MemoryKv {
    entries: Arc<RwLock<BTreeMap<Vec<u8>, MemoryValue>>>,
    /// What each key written since the last flush held before its first
    /// write in that span (`None`: absent), for [`KvStore::rollback`].
    /// Cleared by every flush.
    undo: Arc<Mutex<UndoJournal>>,
}

/// A value [`MemoryKv`] holds, wiped when it goes.
type MemoryValue = zeroize::Zeroizing<Vec<u8>>;

/// Each key's value before an operation's first write to it (`None`: absent).
type UndoJournal = BTreeMap<Vec<u8>, Option<MemoryValue>>;

/// Counts only: the values are secrets.
impl std::fmt::Debug for MemoryKv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pending = self.undo.lock().map(|undo| undo.len()).unwrap_or(0);
        f.debug_struct("MemoryKv")
            .field("entries", &self.len())
            .field("written_since_flush", &pending)
            .finish_non_exhaustive()
    }
}

/// One of [`PeachyStorage::envelope_epochs`]: the epoch, whether every leaf of it
/// read envelopes keyed by it, and its envelope secret.
pub(crate) type EnvelopeEpoch = (u64, bool, zeroize::Zeroizing<[u8; 32]>);

impl MemoryKv {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many entries the store holds. Test-facing, and the reason
    /// `entries` itself stays private.
    pub fn len(&self) -> usize {
        self.entries.read().map(|map| map.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A poisoned lock means a thread panicked while holding it. The crate denies
/// `unwrap` for exactly this case: the answer is an error the caller can see,
/// not a second panic on top of the first.
fn poisoned(what: &str) -> KvError {
    KvError::new(format!("the in-memory store's lock is poisoned ({what})"))
}

impl KvStore for MemoryKv {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        let map = self.entries.read().map_err(|_| poisoned("get"))?;
        Ok(map.get(key).map(|value| value.to_vec()))
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        let mut map = self.entries.write().map_err(|_| poisoned("put"))?;
        let mut undo = self.undo.lock().map_err(|_| poisoned("put"))?;
        undo.entry(key.to_vec())
            .or_insert_with(|| map.get(key).cloned());
        // The value it replaces is wiped as it drops.
        map.insert(key.to_vec(), zeroize::Zeroizing::new(value.to_vec()));
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        let mut map = self.entries.write().map_err(|_| poisoned("delete"))?;
        let mut undo = self.undo.lock().map_err(|_| poisoned("delete"))?;
        undo.entry(key.to_vec())
            .or_insert_with(|| map.get(key).cloned());
        map.remove(key);
        Ok(())
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<KvEntry>, KvError> {
        let map = self.entries.read().map_err(|_| poisoned("scan"))?;
        Ok(map
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.to_vec()))
            .collect())
    }

    /// Every write is visible at once; the flush only ends the span a
    /// rollback would undo.
    fn flush(&self) -> Result<(), KvError> {
        self.undo.lock().map_err(|_| poisoned("flush"))?.clear();
        Ok(())
    }

    fn rollback(&self) -> Result<(), KvError> {
        let mut map = self.entries.write().map_err(|_| poisoned("rollback"))?;
        let mut undo = self.undo.lock().map_err(|_| poisoned("rollback"))?;
        for (key, before) in std::mem::take(&mut *undo) {
            match before {
                Some(value) => map.insert(key, value),
                None => map.remove(&key),
            };
        }
        Ok(())
    }
}

// ---- The provider -----------------------------------------------------------

/// The backend as [`PeachyStorage`] holds it: every step that fails is
/// noted, and a transaction that lost one is never committed (module docs,
/// §A step that fails part-way).
#[derive(Debug)]
struct Watched {
    inner: Box<dyn KvStore>,
    /// The open transaction lost a step: refuse every write until it is
    /// rolled back, and roll it back where it would have been committed.
    failed: AtomicBool,
    /// Every step that has failed on this store, ever, so a caller can ask
    /// whether one failed during its operation even after a flush inside it
    /// already rolled that transaction back.
    faults: AtomicU64,
}

impl Watched {
    fn new(inner: Box<dyn KvStore>) -> Self {
        Self {
            inner,
            failed: AtomicBool::new(false),
            faults: AtomicU64::new(0),
        }
    }

    fn noted<T>(&self, result: Result<T, KvError>) -> Result<T, KvError> {
        if result.is_err() {
            self.failed.store(true, Ordering::SeqCst);
            self.faults.fetch_add(1, Ordering::SeqCst);
        }
        result
    }

    /// A stored value read back, decoded: a value that does not decode is a
    /// failed step like a refused write (module docs, §A step that fails
    /// part-way), so the transaction it happened in is never committed.
    fn decoded<T>(&self, result: serde_json::Result<T>) -> Result<T, KvError> {
        result.map_err(|err| {
            self.failed.store(true, Ordering::SeqCst);
            self.faults.fetch_add(1, Ordering::SeqCst);
            KvError::from(err)
        })
    }

    /// Every row under `prefix`, each value wiped when it drops.
    ///
    /// This shadows [`KvStore::scan`] for every `self.kv.scan(..)` the store
    /// makes (an inherent method is found before a trait's), so no scan of
    /// [`PeachyStorage`] hands back a value that is freed unwiped: a caller
    /// that wants only the keys, or only whether any row is there, drops the
    /// values it did not look at, and those are kept plaintexts, held
    /// envelopes' seals and epoch secrets as often as not. The trait's own
    /// scan is still there for a caller that names it, which nothing here
    /// does.
    fn scan(&self, prefix: &[u8]) -> Result<Vec<WipedEntry>, KvError> {
        let rows = self.noted(self.inner.scan(prefix))?;
        // Moved in, not copied: each value is wrapped where it lies, and the
        // vector of them is collected in place.
        Ok(rows
            .into_iter()
            .map(|(key, value)| (key, zeroize::Zeroizing::new(value)))
            .collect())
    }

    fn refuse_if_failed(&self) -> Result<(), KvError> {
        if self.failed.load(Ordering::SeqCst) {
            // Counted too: a door that swallowed the first failure and wrote
            // on must still be seen to have lost a step.
            self.faults.fetch_add(1, Ordering::SeqCst);
            return Err(KvError::new(
                "an earlier step of this operation failed; nothing more is written until it is rolled back",
            ));
        }
        Ok(())
    }
}

impl KvStore for Watched {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        self.noted(self.inner.get(key))
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        self.refuse_if_failed()?;
        self.noted(self.inner.put(key, value))
    }

    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        self.refuse_if_failed()?;
        self.noted(self.inner.delete(key))
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<KvEntry>, KvError> {
        self.noted(self.inner.scan(prefix))
    }

    /// Commit, unless a step failed: then roll back and say so. A commit
    /// that itself fails is rolled back too, so what it would have made
    /// durable cannot land later through another path.
    fn flush(&self) -> Result<(), KvError> {
        if self.failed.load(Ordering::SeqCst) {
            self.rollback()?;
            return Err(KvError::new(
                "a step of this operation failed, so none of it was kept",
            ));
        }
        match self.inner.flush() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.faults.fetch_add(1, Ordering::SeqCst);
                let _ = self.rollback();
                Err(err)
            }
        }
    }

    fn rollback(&self) -> Result<(), KvError> {
        let outcome = self.inner.rollback();
        self.failed.store(false, Ordering::SeqCst);
        outcome
    }

    fn erase_superseded(&self) -> Result<bool, KvError> {
        self.inner.erase_superseded()
    }

    fn begin_write(&self) -> Result<(), KvError> {
        self.inner.begin_write()
    }

    fn try_begin_write(&self) -> Result<bool, KvError> {
        self.inner.try_begin_write()
    }

    fn foreign_generation(&self) -> Result<Option<u64>, KvError> {
        self.inner.foreign_generation()
    }
}

impl Drop for Watched {
    /// A transaction that lost a step is rolled back here, before the
    /// backend's own drop (which on SQLite commits what is open) runs.
    fn drop(&mut self) {
        if self.failed.load(Ordering::SeqCst) {
            let _ = self.inner.rollback();
        }
    }
}

/// The storage half of [`PeachyProvider`]: OpenMLS' trait over a [`KvStore`].
#[derive(Debug)]
pub struct PeachyStorage {
    kv: Watched,
}

impl PeachyStorage {
    /// Open a store over `kv`, stamping or checking its schema version.
    ///
    /// Fails when the store was written by a NEWER schema, and only then. An
    /// older store is opened and re-stamped: its rows sit under their own
    /// version byte, so this build cannot read them as its own and cannot
    /// corrupt them either — see [`check_schema_stamp`] for why that asymmetry
    /// is the point of the layout, and where a real migration would hang.
    pub fn open(kv: Box<dyn KvStore>) -> Result<Self, KvError> {
        let kv = Watched::new(kv);
        let stamp_key = schema_stamp_key();
        let stamp = kv.get(&stamp_key)?;
        if check_schema_stamp(stamp.as_deref())? {
            kv.put(&stamp_key, &[STORAGE_SCHEMA_VERSION])?;
            kv.flush()?;
        }
        Ok(Self { kv })
    }

    /// A store that dies with the process.
    pub fn in_memory() -> Self {
        // `open` on a fresh MemoryKv cannot fail: the stamp is absent, so the
        // only fallible step is a put into a map. Spelled with a fallback
        // rather than an unwrap because the crate denies unwrap, and because a
        // poisoned brand-new lock is not worth a panic.
        let kv = MemoryKv::new();
        Self::open(Box::new(kv)).unwrap_or_else(|_| Self {
            kv: Watched::new(Box::new(MemoryKv::new())),
        })
    }

    /// Make everything written since the last flush durable. See the module
    /// header for the window this closes and the one it does not.
    ///
    /// When a step since the last flush failed, nothing is made durable:
    /// the transaction is rolled back and this returns an error (module
    /// docs, §A step that fails part-way).
    pub fn flush(&self) -> Result<(), KvError> {
        self.kv.flush()
    }

    /// Discard everything written since the last flush
    /// ([`KvStore::rollback`]), and with it any failed step's mark.
    pub fn rollback(&self) -> Result<(), KvError> {
        self.kv.rollback()
    }

    /// Whether the open transaction lost a step and waits to be rolled back.
    pub(crate) fn holds_failed_step(&self) -> bool {
        self.kv.failed.load(Ordering::SeqCst)
    }

    /// A count that moves whenever a step fails on this store, or a stored
    /// value fails to encode or decode on this thread. Compared across one
    /// operation on one thread (`Client::synced`), never stored.
    pub(crate) fn fault_count(&self) -> u64 {
        self.kv
            .faults
            .load(Ordering::SeqCst)
            .wrapping_add(CODEC_FAULTS.with(Cell::get))
    }

    /// [`KvStore::erase_superseded`] on the backend.
    pub fn erase_superseded(&self) -> Result<bool, KvError> {
        self.kv.erase_superseded()
    }

    /// [`KvStore::begin_write`] on the backend.
    pub(crate) fn begin_write(&self) -> Result<(), KvError> {
        self.kv.begin_write()
    }

    /// [`KvStore::try_begin_write`] on the backend.
    pub(crate) fn try_begin_write(&self) -> Result<bool, KvError> {
        self.kv.try_begin_write()
    }

    /// [`KvStore::foreign_generation`] on the backend.
    pub(crate) fn foreign_generation(&self) -> Result<Option<u64>, KvError> {
        self.kv.foreign_generation()
    }

    /// Note that this device holds state for `group_id`.
    ///
    /// OpenMLS' trait has no "list the groups" — every getter takes a group id
    /// the caller already has — so the index of which groups exist is Peachy's
    /// to keep. Without it a reopened client would hold a database full of
    /// groups and no way to name one.
    pub fn remember_group(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv
            .put(&storage_key(NS_GROUP_INDEX, group_id), group_id)
    }

    /// Drop `group_id` from the index. The group's own rows go through
    /// OpenMLS' deleters; this is only the index entry.
    pub fn forget_group(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(NS_GROUP_INDEX, group_id))?;
        self.kv.delete(&storage_key(NS_HEAD_READ, group_id))?;
        self.forget_opened(group_id)
    }

    /// When this device last finished reading `group_id`'s head
    /// ([`NS_HEAD_READ`]), in unix milliseconds; `None` for never, or a
    /// record that does not read.
    pub(crate) fn head_read_at(&self, group_id: &[u8]) -> Result<Option<i64>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_HEAD_READ, group_id))?
            .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
            .map(i64::from_be_bytes))
    }

    /// Record that this device finished reading `group_id`'s head at `at_ms`.
    pub(crate) fn set_head_read_at(&self, group_id: &[u8], at_ms: i64) -> Result<(), KvError> {
        self.kv
            .put(&storage_key(NS_HEAD_READ, group_id), &at_ms.to_be_bytes())
    }

    /// Whether this device opened the message with `digest` in `group_id`
    /// ([`NS_OPENED`]).
    pub(crate) fn opened_before(
        &self,
        group_id: &[u8],
        digest: &[u8; 16],
    ) -> Result<bool, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_OPENED, &opened_key(group_id, digest)))?
            .is_some())
    }

    /// Record that this device opened the message with `digest` in
    /// `group_id`, dropping the oldest records once the group holds more than
    /// [`OPENED_KEPT`] (plus the slack that batches the drop).
    pub(crate) fn note_opened(&self, group_id: &[u8], digest: &[u8; 16]) -> Result<(), KvError> {
        if self.opened_before(group_id, digest)? {
            return Ok(());
        }
        // A count of any other length is one this build did not write: start
        // again from zero. Records under it are still read, and the first
        // drop finds them older than anything numbered since.
        let (next, floor) = self
            .kv
            .get(&storage_key(NS_OPENED_COUNT, group_id))?
            .and_then(|raw| <[u8; 16]>::try_from(raw.as_slice()).ok())
            .map_or((0, 0), |raw| {
                let mut next = [0u8; 8];
                let mut floor = [0u8; 8];
                next.copy_from_slice(&raw[..8]);
                floor.copy_from_slice(&raw[8..]);
                (u64::from_be_bytes(next), u64::from_be_bytes(floor))
            });
        self.kv.put(
            &storage_key(NS_OPENED, &opened_key(group_id, digest)),
            &next.to_be_bytes(),
        )?;
        let next = next.saturating_add(1);
        let mut floor = floor.min(next);
        if next - floor > OPENED_KEPT + OPENED_PRUNE_SLACK {
            let keep_from = next - OPENED_KEPT;
            let prefix = storage_key(NS_OPENED, &opened_key(group_id, &[]));
            for (key, value) in self.kv.scan(&prefix)? {
                let seq = value.first_chunk::<8>().map(|raw| u64::from_be_bytes(*raw));
                if seq.is_none_or(|seq| seq < keep_from) {
                    self.kv.delete(&key)?;
                }
            }
            floor = keep_from;
        }
        let mut count = Vec::with_capacity(16);
        count.extend_from_slice(&next.to_be_bytes());
        count.extend_from_slice(&floor.to_be_bytes());
        self.kv.put(&storage_key(NS_OPENED_COUNT, group_id), &count)
    }

    /// Drop every opened-message record of `group_id`.
    pub(crate) fn forget_opened(&self, group_id: &[u8]) -> Result<(), KvError> {
        let prefix = storage_key(NS_OPENED, &opened_key(group_id, &[]));
        for (key, _) in self.kv.scan(&prefix)? {
            self.kv.delete(&key)?;
        }
        self.kv.delete(&storage_key(NS_OPENED_COUNT, group_id))
    }

    /// The account identity key(s) this device holds as `actor_id`'s current
    /// one, sorted; empty when it has pinned none. Stored as the keys' 32 raw
    /// bytes each, concatenated: one key as every build writes it; a store
    /// that holds several reads as several.
    pub fn account_pins(&self, actor_id: &str) -> Result<Vec<[u8; 32]>, KvError> {
        let stored = self
            .kv
            .get(&storage_key(NS_ACCOUNT_PIN, actor_id.as_bytes()))?
            .unwrap_or_default();
        let mut keys: Vec<[u8; 32]> = stored.as_chunks::<32>().0.to_vec();
        keys.sort_unstable();
        keys.dedup();
        Ok(keys)
    }

    /// Pin `keys` as `actor_id`'s current account identity keys.
    pub fn set_account_pins(&self, actor_id: &str, keys: &[[u8; 32]]) -> Result<(), KvError> {
        let mut sorted = keys.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        self.kv.put(
            &storage_key(NS_ACCOUNT_PIN, actor_id.as_bytes()),
            &sorted.concat(),
        )
    }

    /// The account identity keys this device has seen `actor_id` move away
    /// from, sorted; empty when none.
    pub fn account_retired(&self, actor_id: &str) -> Result<Vec<[u8; 32]>, KvError> {
        let stored = self
            .kv
            .get(&storage_key(NS_ACCOUNT_RETIRED, actor_id.as_bytes()))?
            .unwrap_or_default();
        let mut keys: Vec<[u8; 32]> = stored.as_chunks::<32>().0.to_vec();
        keys.sort_unstable();
        keys.dedup();
        Ok(keys)
    }

    /// Replace the keys `actor_id` is recorded as having moved away from.
    pub fn set_account_retired(&self, actor_id: &str, keys: &[[u8; 32]]) -> Result<(), KvError> {
        let mut sorted = keys.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        self.kv.put(
            &storage_key(NS_ACCOUNT_RETIRED, actor_id.as_bytes()),
            &sorted.concat(),
        )
    }

    /// The signed `iat` of the leaf that made `actor_id`'s current pin
    /// current; `None` for a pin with no time recorded.
    pub fn account_pin_since(&self, actor_id: &str) -> Result<Option<i64>, KvError> {
        let stored = self
            .kv
            .get(&storage_key(NS_ACCOUNT_PIN_SINCE, actor_id.as_bytes()))?;
        Ok(stored
            .and_then(|value| <[u8; 8]>::try_from(value.as_slice()).ok())
            .map(i64::from_be_bytes))
    }

    /// Record `issued_at` as the `iat` of the leaf that made `actor_id`'s
    /// current pin current.
    pub fn set_account_pin_since(&self, actor_id: &str, issued_at: i64) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_ACCOUNT_PIN_SINCE, actor_id.as_bytes()),
            &issued_at.to_be_bytes(),
        )
    }

    /// Every actor this device pins a key for with no record of when it
    /// became current.
    pub fn actors_with_undated_pins(&self) -> Result<Vec<String>, KvError> {
        let prefix = namespace_prefix(NS_ACCOUNT_PIN);
        let mut actors = Vec::new();
        for (key, _) in self.kv.scan(&prefix)? {
            let Some(actor) = key
                .strip_prefix(prefix.as_slice())
                .and_then(|raw| std::str::from_utf8(raw).ok())
            else {
                continue;
            };
            if self.account_pin_since(actor)?.is_none() {
                actors.push(actor.to_owned());
            }
        }
        Ok(actors)
    }

    /// Whether this device has dated the pins with no time recorded ([`Self::set_account_pins_dated`]).
    pub fn account_pins_dated(&self) -> Result<bool, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_ACCOUNT_PINS_DATED, b"done"))?
            .is_some())
    }

    /// Record that this device has dated the pins with no time recorded,
    /// once, across every conversation it held.
    pub fn set_account_pins_dated(&self) -> Result<(), KvError> {
        self.kv
            .put(&storage_key(NS_ACCOUNT_PINS_DATED, b"done"), &[1])
    }

    /// The leaves `group_id`'s conversation has settled, sorted; `None` when
    /// no build that keeps the record has read it.
    pub fn account_known_leaves(&self, group_id: &[u8]) -> Result<Option<Vec<[u8; 32]>>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_ACCOUNT_KNOWN_LEAVES, group_id))?
            .map(|value| read_digests(Some(value))))
    }

    /// Replace the leaves `group_id`'s conversation has settled.
    pub fn set_account_known_leaves(
        &self,
        group_id: &[u8],
        leaves: &[[u8; 32]],
    ) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_ACCOUNT_KNOWN_LEAVES, group_id),
            &sorted_digests(leaves),
        )
    }

    /// The leaves `group_id`'s conversation has reported, or accepted in
    /// silence, under a key not the person's current one, sorted; `None`
    /// when no build that keeps the record has read it.
    pub fn account_reported_leaves(
        &self,
        group_id: &[u8],
    ) -> Result<Option<Vec<[u8; 32]>>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_ACCOUNT_REPORTED_LEAVES, group_id))?
            .map(|value| read_digests(Some(value))))
    }

    /// Replace the leaves `group_id`'s conversation has reported.
    pub fn set_account_reported_leaves(
        &self,
        group_id: &[u8],
        leaves: &[[u8; 32]],
    ) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_ACCOUNT_REPORTED_LEAVES, group_id),
            &sorted_digests(leaves),
        )
    }

    /// Drop both leaf records of `group_id`'s conversation, in either
    /// digest: for a group left for good, never across a rejoin.
    pub fn forget_account_leaf_records(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv
            .delete(&storage_key(NS_ACCOUNT_KNOWN_LEAVES, group_id))?;
        self.kv
            .delete(&storage_key(NS_ACCOUNT_REPORTED_LEAVES, group_id))?;
        self.forget_account_moved_while_forgotten(group_id)?;
        self.forget_account_leaf_records_v1(group_id)
    }

    /// Every group id holding a reported-leaves record, with that record:
    /// held copies, leaving ones and copies forgotten for a rejoin alike.
    #[allow(clippy::type_complexity)]
    pub fn account_reported_leaf_records(&self) -> Result<Vec<(Vec<u8>, Vec<[u8; 32]>)>, KvError> {
        let prefix = namespace_prefix(NS_ACCOUNT_REPORTED_LEAVES);
        Ok(self
            .kv
            .scan(&prefix)?
            .into_iter()
            .filter_map(|(key, value)| {
                let group_id = key.strip_prefix(prefix.as_slice())?.to_vec();
                Some((group_id, read_digests(Some(value.to_vec()))))
            })
            .collect())
    }

    /// The account keys each person's pin moved to or off while
    /// `group_id`'s copy was forgotten for a rejoin, by actor.
    pub fn account_moved_while_forgotten(
        &self,
        group_id: &[u8],
    ) -> Result<BTreeMap<String, Vec<[u8; 32]>>, KvError> {
        let prefix = storage_key(
            NS_ACCOUNT_MOVED_WHILE_FORGOTTEN,
            &account_seen_key(group_id, ""),
        );
        let mut moved = BTreeMap::new();
        for (key, value) in self.kv.scan(&prefix)? {
            let Some(actor) = key
                .strip_prefix(prefix.as_slice())
                .and_then(|raw| std::str::from_utf8(raw).ok())
            else {
                continue;
            };
            moved.insert(actor.to_owned(), read_digests(Some(value.to_vec())));
        }
        Ok(moved)
    }

    /// Add `keys` to the account keys `actor_id`'s pin moved to or off
    /// while `group_id`'s copy was forgotten for a rejoin.
    pub fn add_account_moved_while_forgotten(
        &self,
        group_id: &[u8],
        actor_id: &str,
        keys: &[[u8; 32]],
    ) -> Result<(), KvError> {
        let key = storage_key(
            NS_ACCOUNT_MOVED_WHILE_FORGOTTEN,
            &account_seen_key(group_id, actor_id),
        );
        let mut held = read_digests(self.kv.get(&key)?);
        let before = held.len();
        held.extend_from_slice(keys);
        held.sort_unstable();
        held.dedup();
        if held.len() == before {
            return Ok(());
        }
        self.kv.put(&key, &held.concat())
    }

    /// Drop everything [`Self::add_account_moved_while_forgotten`] wrote
    /// for `group_id`.
    pub fn forget_account_moved_while_forgotten(&self, group_id: &[u8]) -> Result<(), KvError> {
        let prefix = storage_key(
            NS_ACCOUNT_MOVED_WHILE_FORGOTTEN,
            &account_seen_key(group_id, ""),
        );
        for (key, _) in self.kv.scan(&prefix)? {
            self.kv.delete(&key)?;
        }
        Ok(())
    }

    /// The two leaf records of `group_id`'s conversation in their version-1
    /// layout, by a digest of the leaf's keys alone (known, then
    /// reported); `None` for a record it never wrote.
    #[allow(clippy::type_complexity)]
    pub fn account_leaf_records_v1(
        &self,
        group_id: &[u8],
    ) -> Result<(Option<Vec<[u8; 32]>>, Option<Vec<[u8; 32]>>), KvError> {
        let known = self
            .kv
            .get(&storage_key(NS_ACCOUNT_KNOWN_LEAVES_V1, group_id))?
            .map(|value| read_digests(Some(value)));
        let reported = self
            .kv
            .get(&storage_key(NS_ACCOUNT_REPORTED_LEAVES_V1, group_id))?
            .map(|value| read_digests(Some(value)));
        Ok((known, reported))
    }

    /// Write `group_id`'s leaf records in their version-1 layout: what a
    /// test needs to stand in for a store written in that layout.
    #[cfg(any(test, feature = "fixture"))]
    pub fn set_account_leaf_records_v1(
        &self,
        group_id: &[u8],
        known: Option<&[[u8; 32]]>,
        reported: Option<&[[u8; 32]]>,
    ) -> Result<(), KvError> {
        if let Some(known) = known {
            self.kv.put(
                &storage_key(NS_ACCOUNT_KNOWN_LEAVES_V1, group_id),
                &sorted_digests(known),
            )?;
        }
        if let Some(reported) = reported {
            self.kv.put(
                &storage_key(NS_ACCOUNT_REPORTED_LEAVES_V1, group_id),
                &sorted_digests(reported),
            )?;
        }
        Ok(())
    }

    /// Drop `group_id`'s version-1 leaf records.
    fn forget_account_leaf_records_v1(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv
            .delete(&storage_key(NS_ACCOUNT_KNOWN_LEAVES_V1, group_id))?;
        self.kv
            .delete(&storage_key(NS_ACCOUNT_REPORTED_LEAVES_V1, group_id))
    }

    /// Whether any version-1 leaf record is left to carry.
    pub(crate) fn holds_account_leaf_records_v1(&self) -> Result<bool, KvError> {
        for namespace in [NS_ACCOUNT_KNOWN_LEAVES_V1, NS_ACCOUNT_REPORTED_LEAVES_V1] {
            if !self.kv.scan(&namespace_prefix(namespace))?.is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Drop every version-1 leaf record, once those of the held
    /// groups are carried over.
    pub fn forget_every_account_leaf_record_v1(&self) -> Result<(), KvError> {
        for namespace in [NS_ACCOUNT_KNOWN_LEAVES_V1, NS_ACCOUNT_REPORTED_LEAVES_V1] {
            for (key, _) in self.kv.scan(&namespace_prefix(namespace))? {
                self.kv.delete(&key)?;
            }
        }
        Ok(())
    }

    /// Record that `actor_id` moved away from `key`.
    pub fn retire_account_key(&self, actor_id: &str, key: &[u8; 32]) -> Result<(), KvError> {
        let mut keys = self.account_retired(actor_id)?;
        if keys.contains(key) {
            return Ok(());
        }
        keys.push(*key);
        keys.sort_unstable();
        self.kv.put(
            &storage_key(NS_ACCOUNT_RETIRED, actor_id.as_bytes()),
            &keys.concat(),
        )
    }

    /// The account identity key(s) `group_id` last showed as `actor_id`'s
    /// current one, sorted; empty when it has shown none. Stored as the keys'
    /// 32 raw bytes each, concatenated, so a value holding several (every
    /// key a conversation showed) reads as a set.
    pub fn account_seen(&self, group_id: &[u8], actor_id: &str) -> Result<Vec<[u8; 32]>, KvError> {
        let stored = self.kv.get(&storage_key(
            NS_ACCOUNT_SEEN,
            &account_seen_key(group_id, actor_id),
        ))?;
        let stored = stored.unwrap_or_default();
        let mut keys: Vec<[u8; 32]> = stored.as_chunks::<32>().0.to_vec();
        keys.sort_unstable();
        keys.dedup();
        Ok(keys)
    }

    /// Record that `group_id` shows `keys` for `actor_id`.
    pub fn set_account_seen(
        &self,
        group_id: &[u8],
        actor_id: &str,
        keys: &[[u8; 32]],
    ) -> Result<(), KvError> {
        let mut sorted = keys.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        self.kv.put(
            &storage_key(NS_ACCOUNT_SEEN, &account_seen_key(group_id, actor_id)),
            &sorted.concat(),
        )
    }

    /// Drop everything [`Self::set_account_seen`] wrote for `group_id`. The
    /// per-actor pins stay: they are about the person, not the group. So do
    /// the conversation's leaf records ([`Self::account_known_leaves`],
    /// [`Self::account_reported_leaves`]): a leaf it already reported is not
    /// reported again when the copy is rebuilt, and the next read keeps only
    /// the leaves its tree still holds. A group left for good drops them
    /// ([`Self::forget_account_leaf_records`]).
    pub fn forget_account_seen(&self, group_id: &[u8]) -> Result<(), KvError> {
        let prefix = storage_key(NS_ACCOUNT_SEEN, &account_seen_key(group_id, ""));
        for (key, _) in self.kv.scan(&prefix)? {
            self.kv.delete(&key)?;
        }
        Ok(())
    }

    /// When this device last rotated its own leaf in `group_id` (Unix
    /// seconds) and how many frames it has sealed there since, if recorded.
    pub fn leaf_rotation(&self, group_id: &[u8]) -> Result<Option<(i64, u64)>, KvError> {
        let Some(bytes) = self.kv.get(&storage_key(NS_LEAF_ROTATION, group_id))? else {
            return Ok(None);
        };
        // A record of any other length is one this build did not write:
        // read as absent, so the fallback (the leaf credential's `iat`)
        // decides rather than a guess.
        let Ok(raw) = <[u8; 16]>::try_from(bytes.as_slice()) else {
            return Ok(None);
        };
        let mut at = [0u8; 8];
        let mut sent = [0u8; 8];
        at.copy_from_slice(&raw[..8]);
        sent.copy_from_slice(&raw[8..]);
        Ok(Some((i64::from_be_bytes(at), u64::from_be_bytes(sent))))
    }

    /// Record the rotation state of this device's own leaf in `group_id`.
    pub fn set_leaf_rotation(&self, group_id: &[u8], at: i64, sent: u64) -> Result<(), KvError> {
        let mut raw = Vec::with_capacity(16);
        raw.extend_from_slice(&at.to_be_bytes());
        raw.extend_from_slice(&sent.to_be_bytes());
        self.kv.put(&storage_key(NS_LEAF_ROTATION, group_id), &raw)
    }

    /// Drop the rotation record of `group_id`, and the mark that the other
    /// person was heard from there.
    pub fn forget_leaf_rotation(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(NS_LEAF_ROTATION, group_id))?;
        self.kv.delete(&storage_key(NS_PEER_HEARD, group_id))
    }

    /// Whether this device has opened an application message from another
    /// person in `group_id` since its own leaf there was last put in the tree.
    /// A record of any other value is one this build did not write, read as
    /// absent: the seven-day and frame-budget rotation still apply.
    pub fn peer_heard(&self, group_id: &[u8]) -> Result<bool, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_PEER_HEARD, group_id))?
            .is_some_and(|bytes| bytes.as_slice() == [1]))
    }

    /// Record that another person was heard from in `group_id`. Written only
    /// when absent, so a busy conversation is not one write per message.
    pub fn note_peer_heard(&self, group_id: &[u8]) -> Result<(), KvError> {
        if self.peer_heard(group_id)? {
            return Ok(());
        }
        self.kv.put(&storage_key(NS_PEER_HEARD, group_id), &[1])
    }

    /// Clear the mark: this device's own leaf in `group_id` is new.
    pub fn clear_peer_heard(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(NS_PEER_HEARD, group_id))
    }

    /// The last call participation counter this device handed out, 0 for
    /// none. A record of any other length is one this build did not write,
    /// read as absent.
    pub fn call_participation_seq(&self) -> Result<u64, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_CALL_PARTICIPATION, b"seq"))?
            .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
            .map_or(0, u64::from_be_bytes))
    }

    /// Record `seq` as the last call participation counter handed out.
    pub fn set_call_participation_seq(&self, seq: u64) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_CALL_PARTICIPATION, b"seq"),
            &seq.to_be_bytes(),
        )
    }

    /// The actor whose Welcome seated this device in `group_id`, if recorded.
    pub fn welcome_sender(&self, group_id: &[u8]) -> Result<Option<String>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_WELCOME_SENDER, group_id))?
            .and_then(|bytes| String::from_utf8(bytes).ok()))
    }

    /// Record who seated this device in `group_id` by a Welcome.
    pub fn set_welcome_sender(&self, group_id: &[u8], actor_id: &str) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_WELCOME_SENDER, group_id),
            actor_id.as_bytes(),
        )
    }

    /// Drop the Welcome sender of `group_id`.
    pub fn forget_welcome_sender(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(NS_WELCOME_SENDER, group_id))
    }

    /// The SHA-256 of the commit message staged in `group_id`, if recorded.
    pub(crate) fn staged_commit(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        self.kv.get(&storage_key(NS_STAGED_COMMIT, group_id))
    }

    /// Record the SHA-256 of the commit message staged in `group_id`.
    pub(crate) fn set_staged_commit(&self, group_id: &[u8], digest: &[u8]) -> Result<(), KvError> {
        self.kv
            .put(&storage_key(NS_STAGED_COMMIT, group_id), digest)
    }

    /// Drop the staged commit's digest of `group_id`.
    pub(crate) fn forget_staged_commit(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(NS_STAGED_COMMIT, group_id))
    }

    /// The roster kept for `group_id` when this device forgot it; empty when
    /// none is kept, or the record does not read.
    pub(crate) fn remembered_roster(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<crate::group::RosterClaim>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_REMEMBERED_ROSTER, group_id))?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default())
    }

    /// Keep `roster` for `group_id`, replacing any kept before.
    pub(crate) fn set_remembered_roster(
        &self,
        group_id: &[u8],
        roster: &[crate::group::RosterClaim],
    ) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_REMEMBERED_ROSTER, group_id),
            &serde_json::to_vec(roster)?,
        )
    }

    /// Drop the roster kept for `group_id`, and everything kept with it: the
    /// group state, the report-only roster, and any own-devices record the
    /// store holds ([`NS_REMEMBERED_OWN_DEVICES`]).
    pub fn forget_remembered_roster(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv
            .delete(&storage_key(NS_REMEMBERED_OWN_DEVICES, group_id))?;
        self.kv
            .delete(&storage_key(NS_REMEMBERED_DEVICES, group_id))?;
        self.kv
            .delete(&storage_key(NS_REMEMBERED_POLICY, group_id))?;
        self.kv
            .delete(&storage_key(NS_REMEMBERED_UNVOUCHED, group_id))?;
        self.kv.delete(&storage_key(NS_REMEMBERED_ROSTER, group_id))
    }

    /// The devices kept for `group_id` when a copy of it was forgotten or
    /// replaced, as (actor, device id); empty when none are kept, or the
    /// record does not read.
    pub(crate) fn remembered_devices(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<(String, String)>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_REMEMBERED_DEVICES, group_id))?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default())
    }

    /// Keep `devices` for `group_id`, replacing any kept before.
    pub(crate) fn set_remembered_devices(
        &self,
        group_id: &[u8],
        devices: &[(String, String)],
    ) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_REMEMBERED_DEVICES, group_id),
            &serde_json::to_vec(devices)?,
        )
    }

    /// Whether this device saw `actor_id`'s last leaf leave `group_id`.
    pub fn departed(&self, group_id: &[u8], actor_id: &str) -> Result<bool, KvError> {
        Ok(self
            .kv
            .get(&storage_key(
                NS_DEPARTED,
                &account_seen_key(group_id, actor_id),
            ))?
            .is_some())
    }

    /// Record that `actor_id`'s last leaf left `group_id`, and drop them from
    /// the roster kept for it ([`Self::remembered_roster`]): a Welcome's
    /// lines are never drawn against a person this device has since seen
    /// leave. Nobody is ever added to that roster here.
    pub(crate) fn set_departed(&self, group_id: &[u8], actor_id: &str) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_DEPARTED, &account_seen_key(group_id, actor_id)),
            &[1],
        )?;
        let mut roster = self.remembered_roster(group_id)?;
        if roster.iter().any(|claim| claim.actor_id == actor_id) {
            roster.retain(|claim| claim.actor_id != actor_id);
            self.set_remembered_roster(group_id, &roster)?;
        }
        Ok(())
    }

    /// Drop the record that `actor_id`'s last leaf left `group_id`: they
    /// hold a leaf there again. A no-op when none is kept.
    pub(crate) fn clear_departed(&self, group_id: &[u8], actor_id: &str) -> Result<(), KvError> {
        self.kv.delete(&storage_key(
            NS_DEPARTED,
            &account_seen_key(group_id, actor_id),
        ))
    }

    /// Drop everything [`Self::set_departed`] wrote for `group_id`.
    pub fn forget_departed(&self, group_id: &[u8]) -> Result<(), KvError> {
        let prefix = storage_key(NS_DEPARTED, &account_seen_key(group_id, ""));
        for (key, _) in self.kv.scan(&prefix)? {
            self.kv.delete(&key)?;
        }
        Ok(())
    }

    /// The rejoin reports waiting for `group_id`, oldest first. A value
    /// holding one report reads as a list of it.
    pub fn rejoin_reports(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<crate::group::RejoinReport>, KvError> {
        let Some(bytes) = self.kv.get(&storage_key(NS_REJOIN_REPORT, group_id))? else {
            return Ok(Vec::new());
        };
        Ok(serde_json::from_slice(&bytes)
            .or_else(|_| serde_json::from_slice(&bytes).map(|one| vec![one]))
            .unwrap_or_default())
    }

    /// Keep `reports` for `group_id` until the client takes them; none drops
    /// the record.
    pub fn set_rejoin_reports(
        &self,
        group_id: &[u8],
        reports: &[crate::group::RejoinReport],
    ) -> Result<(), KvError> {
        if reports.is_empty() {
            return self.forget_rejoin_report(group_id);
        }
        self.kv.put(
            &storage_key(NS_REJOIN_REPORT, group_id),
            &serde_json::to_vec(reports)?,
        )
    }

    /// Drop every rejoin report of `group_id`.
    pub fn forget_rejoin_report(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(NS_REJOIN_REPORT, group_id))
    }

    /// The first millisecond `group_id`'s next rejoin report may be drawn
    /// at ([`NS_REJOIN_DRAW_FLOOR`]); 0 when none was drawn, or the record
    /// does not read.
    pub(crate) fn rejoin_draw_floor(&self, group_id: &[u8]) -> Result<u64, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_REJOIN_DRAW_FLOOR, group_id))?
            .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0))
    }

    /// Record the first millisecond `group_id`'s next rejoin report may be
    /// drawn at.
    pub(crate) fn set_rejoin_draw_floor(&self, group_id: &[u8], floor: u64) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_REJOIN_DRAW_FLOOR, group_id),
            &floor.to_be_bytes(),
        )
    }

    /// Record a last-resort key package this device minted at `at`.
    pub fn note_last_resort(&self, key_package_ref: &[u8], at: i64) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_LAST_RESORT, key_package_ref),
            &at.to_be_bytes(),
        )
    }

    /// Every last-resort key package this device still holds: (raw
    /// KeyPackageRef, Unix second minted). A record of any other length is
    /// one this build did not write, and reads as minted at 0: still a
    /// last-resort package (a Welcome it opens is recorded as taken), and
    /// the oldest there is, so the next prune drops it. Skipping it had
    /// made a seat through it look like a one-time package's.
    pub fn last_resorts(&self) -> Result<Vec<(Vec<u8>, i64)>, KvError> {
        let prefix = namespace_prefix(NS_LAST_RESORT);
        Ok(self
            .kv
            .scan(&prefix)?
            .into_iter()
            .map(|(key, value)| {
                let at = <[u8; 8]>::try_from(value.as_slice())
                    .map(i64::from_be_bytes)
                    .unwrap_or(0);
                (key[prefix.len()..].to_vec(), at)
            })
            .collect())
    }

    /// Erase every signature key pair the store holds, and say whether there
    /// was one.
    ///
    /// Builds before this one wrote the device's key pair, private half
    /// included, under [`NS_SIGNATURE_KEY`] at every open where it differed.
    /// Nothing reads it: the signer is built from the seed handed in at open.
    /// So [`crate::group::Client::new`] calls this on every open, which is a
    /// scan and nothing else on a store that holds none, and a one-way
    /// delete on the first open of a store that holds a signing key kept
    /// beside the seed. The values
    /// read back are wiped before they are dropped.
    ///
    /// The delete never waits for another connection's write lock
    /// ([`KvStore::try_begin_write`]): while one holds it, this returns an
    /// error with nothing written, and the next open tries again.
    pub(crate) fn erase_signature_key_pairs(&self) -> Result<bool, KvError> {
        // Every value wrapped before the first delete: a delete that fails
        // returns early, and the pairs not reached yet are wiped as they drop.
        let entries: Vec<WipedEntry> = self.kv.scan(&namespace_prefix(NS_SIGNATURE_KEY))?;
        if entries.is_empty() {
            return Ok(false);
        }
        if !self.kv.try_begin_write()? {
            return Err(KvError::new(
                "another connection holds the store's write lock",
            ));
        }
        for (key, _) in &entries {
            self.kv.delete(key)?;
        }
        Ok(true)
    }

    /// Drop the index entry of a last-resort key package. The package's own
    /// row goes through OpenMLS' `delete_key_package`.
    pub fn forget_last_resort(&self, key_package_ref: &[u8]) -> Result<(), KvError> {
        self.kv
            .delete(&storage_key(NS_LAST_RESORT, key_package_ref))
    }

    /// The highest epoch recorded for `group_id` ([`NS_EPOCH_MARK`]); `None`
    /// when none is. A record that does not read is `u64::MAX`: a mark this
    /// build cannot read refuses every Welcome rather than none.
    pub(crate) fn epoch_mark(&self, group_id: &[u8]) -> Result<Option<u64>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_EPOCH_MARK, group_id))?
            .map(|bytes| {
                <[u8; 8]>::try_from(bytes.as_slice())
                    .map(u64::from_be_bytes)
                    .unwrap_or(u64::MAX)
            }))
    }

    /// What the group's head said of the held copy of `group_id`
    /// ([`NS_HEAD_CONFIRMED`]). A value this build cannot read is
    /// [`HeadState::Confirmed`]: it fails closed, counting the held epoch
    /// toward the mark and keeping the copy's roster for the Welcome judge.
    pub(crate) fn head_state(&self, group_id: &[u8]) -> Result<HeadState, KvError> {
        Ok(
            match self.kv.get(&storage_key(NS_HEAD_CONFIRMED, group_id))? {
                None => HeadState::Unrecorded,
                Some(bytes) => match bytes.as_slice() {
                    [0] if self
                        .kv
                        .get(&storage_key(NS_COPY_CONTESTED, group_id))?
                        .is_some() =>
                    {
                        HeadState::Contested
                    }
                    [0] => HeadState::Unconfirmed,
                    [2] => HeadState::Lapsed,
                    _ => HeadState::Confirmed,
                },
            },
        )
    }

    /// Whether the held copy of `group_id` is confirmed now
    /// ([`HeadState::Confirmed`]).
    pub(crate) fn head_confirmed(&self, group_id: &[u8]) -> Result<bool, KvError> {
        Ok(self.head_state(group_id)? == HeadState::Confirmed)
    }

    /// Record what the head said of the held copy of `group_id`;
    /// [`HeadState::Unrecorded`] drops the record (the copy is gone).
    pub(crate) fn set_head_state(&self, group_id: &[u8], state: HeadState) -> Result<(), KvError> {
        let key = storage_key(NS_HEAD_CONFIRMED, group_id);
        let contested = storage_key(NS_COPY_CONTESTED, group_id);
        if state == HeadState::Contested {
            self.kv.put(&contested, &[1])?;
        } else {
            self.kv.delete(&contested)?;
        }
        match state {
            HeadState::Unrecorded => self.kv.delete(&key),
            HeadState::Unconfirmed | HeadState::Contested => self.kv.put(&key, &[0]),
            HeadState::Confirmed => self.kv.put(&key, &[1]),
            HeadState::Lapsed => self.kv.put(&key, &[2]),
        }
    }

    /// The head given when the copy of `group_id` was seated below it
    /// ([`NS_JOIN_HEAD`]); `None` when none is kept or the record does not
    /// read.
    pub(crate) fn join_head(&self, group_id: &[u8]) -> Result<Option<(u64, [u8; 32])>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_JOIN_HEAD, group_id))?
            .and_then(|bytes| {
                let epoch = <[u8; 8]>::try_from(bytes.get(..8)?).ok()?;
                let verifier = <[u8; 32]>::try_from(bytes.get(8..)?).ok()?;
                Some((u64::from_be_bytes(epoch), verifier))
            }))
    }

    /// Keep the head given at the join of the copy of `group_id`.
    pub(crate) fn set_join_head(
        &self,
        group_id: &[u8],
        epoch: u64,
        verifier: &[u8; 32],
    ) -> Result<(), KvError> {
        let mut value = epoch.to_be_bytes().to_vec();
        value.extend_from_slice(verifier);
        self.kv.put(&storage_key(NS_JOIN_HEAD, group_id), &value)
    }

    /// Drop the join head of `group_id`.
    pub(crate) fn forget_join_head(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(NS_JOIN_HEAD, group_id))
    }

    /// The verifiers the copy of `group_id` had at its last
    /// [`COPY_VERIFIERS_KEPT`] epochs ([`NS_COPY_VERIFIERS`]), oldest first.
    /// A record that does not read is empty: it confirms nothing and
    /// contradicts nothing.
    pub(crate) fn copy_verifiers(&self, group_id: &[u8]) -> Result<Vec<(u64, [u8; 32])>, KvError> {
        let mut kept = self.copy_verifier_records(group_id)?;
        kept.drain(..kept.len().saturating_sub(COPY_VERIFIERS_KEPT));
        Ok(kept)
    }

    /// Whether the copy of `group_id` has entered more than
    /// [`COPY_VERIFIERS_KEPT`] epochs since its seat, so that the seat is no
    /// longer among the kept ones: the record holds one more epoch than the
    /// window once it has.
    pub(crate) fn copy_walked_past_seat(&self, group_id: &[u8]) -> Result<bool, KvError> {
        Ok(self.copy_verifier_records(group_id)?.len() > COPY_VERIFIERS_KEPT)
    }

    fn copy_verifier_records(&self, group_id: &[u8]) -> Result<Vec<(u64, [u8; 32])>, KvError> {
        let Some(bytes) = self.kv.get(&storage_key(NS_COPY_VERIFIERS, group_id))? else {
            return Ok(Vec::new());
        };
        if bytes.len() % 40 != 0 {
            return Ok(Vec::new());
        }
        Ok(bytes
            .as_chunks::<40>()
            .0
            .iter()
            .filter_map(|chunk| {
                let epoch = <[u8; 8]>::try_from(&chunk[..8]).ok()?;
                let verifier = <[u8; 32]>::try_from(&chunk[8..]).ok()?;
                Some((u64::from_be_bytes(epoch), verifier))
            })
            .collect())
    }

    /// Record that the copy of `group_id` had `verifier` at `epoch`: the
    /// record of that epoch is replaced, and only the last
    /// [`COPY_VERIFIERS_KEPT`] epochs are kept, plus the one before them once
    /// there is one ([`Self::copy_walked_past_seat`]).
    pub(crate) fn note_copy_verifier(
        &self,
        group_id: &[u8],
        epoch: u64,
        verifier: &[u8; 32],
    ) -> Result<(), KvError> {
        let mut kept = self.copy_verifier_records(group_id)?;
        kept.retain(|(at, _)| *at != epoch);
        kept.push((epoch, *verifier));
        kept.sort_by_key(|(at, _)| *at);
        kept.drain(..kept.len().saturating_sub(COPY_VERIFIERS_KEPT + 1));
        let mut value = Vec::with_capacity(kept.len() * 40);
        for (at, v) in &kept {
            value.extend_from_slice(&at.to_be_bytes());
            value.extend_from_slice(v);
        }
        self.kv
            .put(&storage_key(NS_COPY_VERIFIERS, group_id), &value)
    }

    /// The envelope secrets the copy of `group_id` had at its last epochs
    /// ([`NS_ENVELOPE_EPOCHS`]), oldest first, each with whether every leaf
    /// of that epoch read envelopes keyed by it. A record that does not read
    /// is empty: it opens nothing.
    pub(crate) fn envelope_epochs(&self, group_id: &[u8]) -> Result<Vec<EnvelopeEpoch>, KvError> {
        // Copied out, not moved: collecting the records' own iterator would
        // write the pairs into the records' block, and the bytes past them,
        // secrets among them, would be freed unwiped. The records wipe
        // their own as they drop.
        let records = self.envelope_epoch_records(group_id)?;
        Ok(records
            .iter()
            .map(|record| {
                (
                    record.epoch,
                    record.all_read_it,
                    zeroize::Zeroizing::new(*record.secret),
                )
            })
            .collect())
    }

    /// The whole records [`Self::envelope_epochs`] reads, oldest first, with
    /// the leaves each epoch's leaving commit added. Records that do not
    /// parse end the list.
    pub(crate) fn envelope_epoch_records(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<EnvelopeEpochRecord>, KvError> {
        let Some(bytes) = self.kv.get(&storage_key(NS_ENVELOPE_EPOCHS, group_id))? else {
            return Ok(Vec::new());
        };
        let bytes = zeroize::Zeroizing::new(bytes);
        // Room for every record the bytes can hold, so the list never grows:
        // a Vec that grows copies the secrets into a new block and frees the
        // old one unwiped.
        let mut records = Vec::with_capacity(bytes.len() / 42);
        let mut rest = bytes.as_slice();
        while !rest.is_empty() {
            let Some((head, tail)) = rest.split_at_checked(42) else {
                break;
            };
            let (Ok(epoch), Ok(secret)) = (
                <[u8; 8]>::try_from(&head[..8]),
                <[u8; 32]>::try_from(&head[9..41]),
            ) else {
                break;
            };
            let count = head[41];
            let (added_next, tail) = if count == ADDED_UNKNOWN {
                (None, tail)
            } else {
                let Some((digests, tail)) = tail.split_at_checked(usize::from(count) * 32) else {
                    break;
                };
                let digests = digests.as_chunks::<32>().0.to_vec();
                (Some(digests), tail)
            };
            records.push(EnvelopeEpochRecord {
                epoch: u64::from_be_bytes(epoch),
                all_read_it: head[8] == 1,
                secret: Secret::new(secret),
                added_next,
            });
            rest = tail;
        }
        Ok(records)
    }

    /// Record that the copy of `group_id` had `secret` at `epoch`: the record
    /// of that epoch is replaced, and only the last `kept` epochs are kept.
    /// `added_next`, when given, is the leaves the commit leaving `epoch`
    /// adds (digests of their device keys); when not, a record already held
    /// for `epoch` keeps the adds it noted.
    pub(crate) fn note_envelope_epoch(
        &self,
        group_id: &[u8],
        epoch: u64,
        all_read_it: bool,
        secret: &[u8; 32],
        kept: usize,
        added_next: Option<Vec<[u8; 32]>>,
    ) -> Result<(), KvError> {
        let held = self.envelope_epoch_records(group_id)?;
        let earlier_adds = held
            .iter()
            .find(|record| record.epoch == epoch)
            .and_then(|record| record.added_next.clone());
        let noted = EnvelopeEpochRecord {
            epoch,
            all_read_it,
            secret: Secret::new(*secret),
            added_next: added_next.or(earlier_adds),
        };
        // Picked and ordered by reference: `held` is never changed, so each
        // record wipes its secret where it was read. Retaining, sorting or
        // draining the records themselves would shift them down the list and
        // leave the bytes of those that moved, secrets among them, past its
        // end, freed unwiped with it.
        let mut picked: Vec<&EnvelopeEpochRecord> = held
            .iter()
            .filter(|record| record.epoch != epoch)
            .chain(std::iter::once(&noted))
            .collect();
        picked.sort_by_key(|record| record.epoch);
        let picked = &picked[picked.len().saturating_sub(kept)..];
        // Sized exactly, so the buffer never grows and leaves a copy of a
        // secret behind; wiped when it drops.
        let size: usize = picked
            .iter()
            .map(|record| 42 + record.added_next.as_ref().map_or(0, |d| d.len() * 32))
            .sum();
        let mut value = zeroize::Zeroizing::new(Vec::with_capacity(size));
        for record in picked {
            value.extend_from_slice(&record.epoch.to_be_bytes());
            value.push(u8::from(record.all_read_it));
            value.extend_from_slice(&record.secret[..]);
            match &record.added_next {
                Some(digests) if digests.len() < usize::from(ADDED_UNKNOWN) => {
                    value.push(u8::try_from(digests.len()).unwrap_or(ADDED_UNKNOWN));
                    for digest in digests {
                        value.extend_from_slice(digest);
                    }
                }
                _ => value.push(ADDED_UNKNOWN),
            }
        }
        self.kv
            .put(&storage_key(NS_ENVELOPE_EPOCHS, group_id), &value)
    }

    /// The envelope secrets handed back for the epochs this device's seat in
    /// `group_id` was held while its copy could not follow ([`NS_ENVELOPE_GAP`]).
    pub(crate) fn envelope_gap(
        &self,
        group_id: &[u8],
    ) -> Result<crate::welcome_frame::GapSecrets, KvError> {
        let Some(bytes) = self.kv.get(&storage_key(NS_ENVELOPE_GAP, group_id))? else {
            return Ok(crate::welcome_frame::GapSecrets::default());
        };
        let bytes = zeroize::Zeroizing::new(bytes);
        let chunks = bytes.as_chunks::<40>().0;
        let mut gap = crate::welcome_frame::GapSecrets::new(Vec::with_capacity(chunks.len()));
        for chunk in chunks {
            let (epoch, secret) = chunk.split_at(8);
            if let (Ok(epoch), Ok(secret)) =
                (<[u8; 8]>::try_from(epoch), <[u8; 32]>::try_from(secret))
            {
                gap.push((u64::from_be_bytes(epoch), secret));
            }
        }
        Ok(gap)
    }

    /// Replace the gap secrets kept for `group_id`; none drops the record.
    pub(crate) fn set_envelope_gap(
        &self,
        group_id: &[u8],
        gap: &[(u64, [u8; 32])],
    ) -> Result<(), KvError> {
        let key = storage_key(NS_ENVELOPE_GAP, group_id);
        if gap.is_empty() {
            return self.kv.delete(&key);
        }
        let mut value = zeroize::Zeroizing::new(Vec::with_capacity(gap.len() * 40));
        for (epoch, secret) in gap {
            value.extend_from_slice(&epoch.to_be_bytes());
            value.extend_from_slice(secret);
        }
        self.kv.put(&key, &value)
    }

    /// The envelopes held because they opened for no group
    /// ([`NS_HELD_ENVELOPES`]), oldest first. Records that do not parse end
    /// the list.
    pub(crate) fn held_envelopes(&self) -> Result<Vec<HeldEnvelope>, KvError> {
        let Some(bytes) = self.kv.get(&storage_key(NS_HELD_ENVELOPES, b""))? else {
            return Ok(Vec::new());
        };
        let mut held = Vec::new();
        let mut rest = bytes.as_slice();
        while !rest.is_empty() {
            let Some((head, tail)) = rest.split_at_checked(11) else {
                break;
            };
            let mailbox_kind = head[0];
            let Ok(at) = <[u8; 8]>::try_from(&head[1..9]) else {
                break;
            };
            let id_len = usize::from(u16::from_be_bytes([head[9], head[10]]));
            let Some((id, tail)) = tail.split_at_checked(id_len) else {
                break;
            };
            let Ok(id) = String::from_utf8(id.to_vec()) else {
                break;
            };
            let Some((len, tail)) = tail.split_at_checked(4) else {
                break;
            };
            let Ok(len) = <[u8; 4]>::try_from(len) else {
                break;
            };
            let Ok(len) = usize::try_from(u32::from_be_bytes(len)) else {
                break;
            };
            let Some((envelope, tail)) = tail.split_at_checked(len) else {
                break;
            };
            held.push(HeldEnvelope {
                mailbox_kind,
                received_at_ms: u64::from_be_bytes(at),
                id,
                envelope: envelope.to_vec(),
            });
            rest = tail;
        }
        Ok(held)
    }

    /// Every envelope held on its device seal ([`NS_HELD_SEALED`]), oldest
    /// first. A record that does not read is left out (and swept by
    /// [`Self::sweep_sealed_holds`]).
    pub(crate) fn sealed_holds(&self) -> Result<Vec<SealedHold>, KvError> {
        let prefix = namespace_prefix(NS_HELD_SEALED);
        let mut held: Vec<SealedHold> = self
            .kv
            .scan(&prefix)?
            .into_iter()
            .filter_map(|(key, value)| {
                let digest: [u8; 32] = key.get(prefix.len()..)?.try_into().ok()?;
                SealedHold::decode(digest, &value)
            })
            .collect();
        held.sort_by_key(|h| (h.received_at_ms, h.digest));
        Ok(held)
    }

    /// The envelope held on its device seal under `digest`, if any.
    pub(crate) fn sealed_hold(&self, digest: &[u8; 32]) -> Result<Option<SealedHold>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_HELD_SEALED, digest))?
            .map(zeroize::Zeroizing::new)
            .and_then(|raw| SealedHold::decode(*digest, &raw)))
    }

    /// The bytes of the envelope held on its device seal under `digest`.
    pub(crate) fn sealed_hold_envelope(
        &self,
        digest: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, KvError> {
        self.kv.get(&storage_key(NS_HELD_BODY, digest))
    }

    /// Keep (or rewrite) `hold`'s record; `envelope`, when given, beside it.
    pub(crate) fn set_sealed_hold(
        &self,
        hold: &SealedHold,
        envelope: Option<&[u8]>,
    ) -> Result<(), KvError> {
        let value = hold
            .encode()
            .ok_or_else(|| KvError::new("a held envelope's record does not frame"))?;
        if let Some(envelope) = envelope {
            self.kv
                .put(&storage_key(NS_HELD_BODY, &hold.digest), envelope)?;
        }
        self.kv
            .put(&storage_key(NS_HELD_SEALED, &hold.digest), &value)
    }

    /// Drop the envelope held under `digest` and its record.
    pub(crate) fn delete_sealed_hold(&self, digest: &[u8; 32]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(NS_HELD_SEALED, digest))?;
        self.kv.delete(&storage_key(NS_HELD_BODY, digest))
    }

    /// Drop every record of [`NS_HELD_SEALED`] that does not read or has no
    /// envelope beside it, and every envelope with no record: what a write
    /// cut short or a build with another layout left.
    pub(crate) fn sweep_sealed_holds(&self) -> Result<(), KvError> {
        let records = namespace_prefix(NS_HELD_SEALED);
        let bodies = namespace_prefix(NS_HELD_BODY);
        let body_keys: std::collections::BTreeSet<Vec<u8>> = self
            .kv
            .scan(&bodies)?
            .into_iter()
            .filter_map(|(key, _)| key.get(bodies.len()..).map(<[u8]>::to_vec))
            .collect();
        let mut live = std::collections::BTreeSet::new();
        for (key, value) in self.kv.scan(&records)? {
            let digest = key.get(records.len()..).unwrap_or_default().to_vec();
            let reads = <[u8; 32]>::try_from(digest.as_slice())
                .ok()
                .and_then(|d| SealedHold::decode(d, &value))
                .is_some();
            if reads && body_keys.contains(&digest) {
                live.insert(digest);
            } else {
                self.kv.delete(&key)?;
            }
        }
        for digest in body_keys.difference(&live) {
            self.kv.delete(&storage_key(NS_HELD_BODY, digest))?;
        }
        Ok(())
    }

    /// Whether an envelope with this SHA-256 was held on its seal and
    /// released ([`NS_HELD_RELEASED`]).
    pub(crate) fn held_released(&self, digest: &[u8; 32]) -> Result<bool, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_HELD_RELEASED, digest))?
            .is_some())
    }

    /// Note that the envelope with this SHA-256 was released at `now`.
    pub(crate) fn note_held_released(&self, digest: &[u8; 32], now: u64) -> Result<(), KvError> {
        self.kv
            .put(&storage_key(NS_HELD_RELEASED, digest), &now.to_be_bytes())
    }

    /// Drop the release notes from before `oldest_ms` and any that do not
    /// read, then the oldest past `kept`.
    pub(crate) fn prune_held_released(&self, oldest_ms: u64, kept: usize) -> Result<(), KvError> {
        let mut live: Vec<(u64, Vec<u8>)> = Vec::new();
        for (key, value) in self.kv.scan(&namespace_prefix(NS_HELD_RELEASED))? {
            match <[u8; 8]>::try_from(value.as_slice()).map(u64::from_be_bytes) {
                Ok(at) if at >= oldest_ms => live.push((at, key)),
                _ => self.kv.delete(&key)?,
            }
        }
        if live.len() > kept {
            live.sort();
            for (_, key) in live.drain(..live.len() - kept) {
                self.kv.delete(&key)?;
            }
        }
        Ok(())
    }

    /// Who each device key of `group_id` belonged to ([`NS_LEAF_PEOPLE`]).
    /// A record that does not read is none.
    pub(crate) fn leaf_people(&self, group_id: &[u8]) -> Result<Option<LeafPeople>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_LEAF_PEOPLE, group_id))?
            .and_then(|raw| LeafPeople::decode(&raw)))
    }

    /// Drop what [`NS_LEAF_PEOPLE`] keeps for `group_id`.
    pub(crate) fn forget_leaf_people(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(NS_LEAF_PEOPLE, group_id))
    }

    /// Replace what [`NS_LEAF_PEOPLE`] keeps for `group_id`.
    pub(crate) fn set_leaf_people(
        &self,
        group_id: &[u8],
        people: &LeafPeople,
    ) -> Result<(), KvError> {
        self.kv
            .put(&storage_key(NS_LEAF_PEOPLE, group_id), &people.encode())
    }

    /// Every device key any group's [`NS_LEAF_PEOPLE`] record holds, with
    /// the actor id it named: read in one scan, for a reopen pass that meets
    /// a key its own group's record does not hold. Only ever a hint of whose
    /// a key is; never a word that they were in another group.
    pub(crate) fn leaf_people_index(
        &self,
    ) -> Result<std::collections::HashMap<[u8; 32], String>, KvError> {
        let mut index = std::collections::HashMap::new();
        for (_, value) in self.kv.scan(&namespace_prefix(NS_LEAF_PEOPLE))? {
            if let Some(people) = LeafPeople::decode(&value) {
                for person in people.people {
                    index.entry(person.key).or_insert(person.actor_id);
                }
            }
        }
        Ok(index)
    }

    /// Drop the [`NS_LEAF_PEOPLE`] records of groups let go before
    /// `oldest_ms`, and any that do not read; a time ahead of `now` is set
    /// to `now` ([`LeafPeople::clamp_left_at`]) and kept.
    pub(crate) fn prune_leaf_people(&self, oldest_ms: u64, now: u64) -> Result<(), KvError> {
        for (key, value) in self.kv.scan(&namespace_prefix(NS_LEAF_PEOPLE))? {
            match LeafPeople::decode(&value) {
                Some(mut people)
                    if people.forgotten_at_ms == 0 || people.forgotten_at_ms >= oldest_ms =>
                {
                    if people.clamp_left_at(now) {
                        self.kv.put(&key, &people.encode())?;
                    }
                }
                _ => self.kv.delete(&key)?,
            }
        }
        Ok(())
    }

    /// Replace the held envelopes; none drops the record.
    pub(crate) fn set_held_envelopes(&self, held: &[HeldEnvelope]) -> Result<(), KvError> {
        let key = storage_key(NS_HELD_ENVELOPES, b"");
        if held.is_empty() {
            return self.kv.delete(&key);
        }
        let mut value = Vec::new();
        for entry in held {
            let (Ok(id_len), Ok(len)) = (
                u16::try_from(entry.id.len()),
                u32::try_from(entry.envelope.len()),
            ) else {
                continue;
            };
            value.push(entry.mailbox_kind);
            value.extend_from_slice(&entry.received_at_ms.to_be_bytes());
            value.extend_from_slice(&id_len.to_be_bytes());
            value.extend_from_slice(entry.id.as_bytes());
            value.extend_from_slice(&len.to_be_bytes());
            value.extend_from_slice(&entry.envelope);
        }
        self.kv.put(&key, &value)
    }

    /// What the message with `digest` under mailbox id `id` opened to,
    /// when it is kept ([`NS_OPENED_CONTENT`]). A record that does not read
    /// is none.
    pub(crate) fn opened_content(
        &self,
        id: &str,
        digest: &[u8; 16],
    ) -> Result<Option<OpenedContent>, KvError> {
        Ok(self
            .kv
            .get(&opened_content_key(id, Some(digest)))?
            .map(zeroize::Zeroizing::new)
            .and_then(|raw| OpenedContent::decode(&raw)))
    }

    /// Whether anything is kept under mailbox id `id`, for any message.
    pub(crate) fn holds_opened_content(&self, id: &str) -> Result<bool, KvError> {
        Ok(!self.kv.scan(&opened_content_key(id, None))?.is_empty())
    }

    /// Keep what the message under mailbox id `id` opened to, beside
    /// anything kept under the id for another message. A record too large to
    /// frame (a group id or a name over 64 KiB) is refused as a write is.
    pub(crate) fn keep_opened_content(
        &self,
        id: &str,
        content: &OpenedContent,
    ) -> Result<(), KvError> {
        let value = content
            .encode()
            .ok_or_else(|| KvError::new("an opened message's record does not frame"))?;
        self.kv
            .put(&opened_content_key(id, Some(&content.digest)), &value)
    }

    /// Drop everything kept under mailbox id `id`; answers whether there was
    /// a record.
    pub(crate) fn release_opened_content(&self, id: &str) -> Result<bool, KvError> {
        let kept = self.kv.scan(&opened_content_key(id, None))?;
        for (key, _) in &kept {
            self.kv.delete(key)?;
        }
        Ok(!kept.is_empty())
    }

    /// Drop the records kept before `oldest_ms` and any that do not read,
    /// then the oldest past `kept`.
    pub(crate) fn prune_opened_content(&self, oldest_ms: u64, kept: usize) -> Result<(), KvError> {
        let mut live: Vec<(u64, Vec<u8>)> = Vec::new();
        // Every plaintext comes wrapped ([`Watched::scan`]): a delete that
        // fails returns early, and the values not reached yet are wiped as
        // they drop.
        let entries = self.kv.scan(&namespace_prefix(NS_OPENED_CONTENT))?;
        for (key, value) in entries {
            match OpenedContent::decode(&value) {
                Some(record) if record.kept_at_ms >= oldest_ms => {
                    live.push((record.kept_at_ms, key));
                }
                _ => self.kv.delete(&key)?,
            }
        }
        if live.len() > kept {
            live.sort_by_key(|(at, _)| *at);
            for (_, key) in live.drain(..live.len() - kept) {
                self.kv.delete(&key)?;
            }
        }
        Ok(())
    }

    /// The steward keys kept for `group_id` ([`NS_STEWARD_KEYS`]): epoch,
    /// when written, key; oldest first. A record that does not read is
    /// empty.
    pub(crate) fn steward_keys(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<(u64, i64, [u8; 32])>, KvError> {
        let Some(bytes) = self.kv.get(&storage_key(NS_STEWARD_KEYS, group_id))? else {
            return Ok(Vec::new());
        };
        if bytes.len() % 48 != 0 {
            return Ok(Vec::new());
        }
        Ok(bytes
            .as_chunks::<48>()
            .0
            .iter()
            .filter_map(|chunk| {
                let epoch = <[u8; 8]>::try_from(&chunk[..8]).ok()?;
                let at = <[u8; 8]>::try_from(&chunk[8..16]).ok()?;
                let key = <[u8; 32]>::try_from(&chunk[16..]).ok()?;
                Some((u64::from_be_bytes(epoch), i64::from_be_bytes(at), key))
            })
            .collect())
    }

    /// Record that the meta of `group_id` named `key` at `epoch`, written
    /// at `now`: the record of that epoch is replaced, those written more
    /// than [`crate::steward::STEWARD_KEY_KEPT_SECONDS`] before `now` go, and
    /// only the last [`COPY_VERIFIERS_KEPT`] epochs and the one before them
    /// are kept: a veto further back is judged by reading the head anyway.
    pub(crate) fn note_steward_key(
        &self,
        group_id: &[u8],
        epoch: u64,
        now: i64,
        key: &[u8; 32],
    ) -> Result<(), KvError> {
        let mut kept = self.steward_keys(group_id)?;
        let horizon = now.saturating_sub(crate::steward::STEWARD_KEY_KEPT_SECONDS);
        kept.retain(|(at, written, _)| *at != epoch && *written >= horizon);
        kept.push((epoch, now, *key));
        kept.sort_by_key(|(at, _, _)| *at);
        kept.drain(..kept.len().saturating_sub(COPY_VERIFIERS_KEPT + 1));
        let mut value = Vec::with_capacity(kept.len() * 48);
        for (at, written, k) in &kept {
            value.extend_from_slice(&at.to_be_bytes());
            value.extend_from_slice(&written.to_be_bytes());
            value.extend_from_slice(k);
        }
        self.kv.put(&storage_key(NS_STEWARD_KEYS, group_id), &value)
    }

    /// The hold of `group_id` ([`NS_GROUP_HOLD`]), lapsed or not; `None` for
    /// none, or a record that does not read.
    pub(crate) fn group_hold(
        &self,
        group_id: &[u8],
    ) -> Result<Option<crate::steward::GroupHold>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_GROUP_HOLD, group_id))?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok()))
    }

    /// Set or drop the hold of `group_id`.
    pub(crate) fn set_group_hold(
        &self,
        group_id: &[u8],
        hold: Option<&crate::steward::GroupHold>,
    ) -> Result<(), KvError> {
        let key = storage_key(NS_GROUP_HOLD, group_id);
        match hold {
            None => self.kv.delete(&key),
            // A plain struct of numbers and a unit enum always serializes;
            // were it not to, the empty value reads as no hold.
            Some(hold) => self
                .kv
                .put(&key, &serde_json::to_vec(hold).unwrap_or_default()),
        }
    }

    /// The steward key the last merged commit's stamp named in `group_id`
    /// ([`NS_STAMP_STEWARD`]); `None` for none, or a record that does not
    /// read.
    pub(crate) fn stamp_steward(&self, group_id: &[u8]) -> Result<Option<[u8; 32]>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_STAMP_STEWARD, group_id))?
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok()))
    }

    /// Record the steward key a merged commit's stamp named (`None`: the
    /// stamp named none).
    pub(crate) fn set_stamp_steward(
        &self,
        group_id: &[u8],
        key: Option<&[u8; 32]>,
    ) -> Result<(), KvError> {
        let at = storage_key(NS_STAMP_STEWARD, group_id);
        match key {
            None => self.kv.delete(&at),
            Some(key) => self.kv.put(&at, key),
        }
    }

    /// What the stamps the copy of `group_id` opened since its seat said of a
    /// steward ([`NS_STAMPS_OPENED`]): `None` for none opened, `Some(false)`
    /// when every one named none, `Some(true)` when one named a key (or the
    /// record does not read).
    pub(crate) fn stamps_named_steward(&self, group_id: &[u8]) -> Result<Option<bool>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_STAMPS_OPENED, group_id))?
            .map(|bytes| bytes.as_slice() != [0u8]))
    }

    /// Record a stamp the copy of `group_id` opened, which named a steward
    /// key when `named`. Once one has named a key the record stays so.
    pub(crate) fn note_stamp_opened(&self, group_id: &[u8], named: bool) -> Result<(), KvError> {
        let at = storage_key(NS_STAMPS_OPENED, group_id);
        if named {
            return self.kv.put(&at, &[1u8]);
        }
        if self.kv.get(&at)?.is_none() {
            self.kv.put(&at, &[0u8])?;
        }
        Ok(())
    }

    /// The steward key `group_id` counts in place of its meta's
    /// ([`NS_COUNTED_STEWARD`]): `None` when the meta's counts, `Some(None)`
    /// when none counts. A record that does not read counts none.
    pub(crate) fn counted_steward(
        &self,
        group_id: &[u8],
    ) -> Result<Option<Option<[u8; 32]>>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_COUNTED_STEWARD, group_id))?
            .map(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok()))
    }

    /// When the last hold of `group_id` began ([`NS_HOLD_STARTED`]).
    pub(crate) fn hold_started(&self, group_id: &[u8]) -> Result<Option<i64>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_HOLD_STARTED, group_id))?
            .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
            .map(i64::from_be_bytes))
    }

    /// Record that a hold of `group_id` began at `since`.
    pub(crate) fn set_hold_started(&self, group_id: &[u8], since: i64) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_HOLD_STARTED, group_id),
            &since.to_be_bytes(),
        )
    }

    /// How many repeat holds of `group_id` began since its last full hold
    /// ([`NS_HOLD_REPEATS`]); 0 for none. A record that does not read counts
    /// as every repeat spent, so it buys no further hold.
    pub(crate) fn hold_repeats(&self, group_id: &[u8]) -> Result<u32, KvError> {
        Ok(
            match self.kv.get(&storage_key(NS_HOLD_REPEATS, group_id))? {
                None => 0,
                Some(bytes) => <[u8; 4]>::try_from(bytes.as_slice())
                    .map(u32::from_be_bytes)
                    .unwrap_or(u32::MAX),
            },
        )
    }

    /// Record that `repeats` repeat holds of `group_id` began since its last
    /// full hold; 0 drops the record.
    pub(crate) fn set_hold_repeats(&self, group_id: &[u8], repeats: u32) -> Result<(), KvError> {
        let at = storage_key(NS_HOLD_REPEATS, group_id);
        if repeats == 0 {
            return self.kv.delete(&at);
        }
        self.kv.put(&at, &repeats.to_be_bytes())
    }

    /// Whether a copy of `group_id` was forgotten while a hold was on record
    /// since its last full hold ([`NS_HOLD_REJOINED`]).
    pub(crate) fn hold_rejoined(&self, group_id: &[u8]) -> Result<bool, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_HOLD_REJOINED, group_id))?
            .is_some())
    }

    /// Drop every record of `group_id`'s past holds ([`NS_HOLD_STARTED`],
    /// [`NS_HOLD_REPEATS`], [`NS_HOLD_REJOINED`]), for a group the person
    /// left for good: a store read later keeps no sign the group was ever
    /// stalled. A seat in it later starts the day's holds afresh.
    pub(crate) fn forget_hold_history(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(NS_HOLD_STARTED, group_id))?;
        self.kv.delete(&storage_key(NS_HOLD_REPEATS, group_id))?;
        self.kv.delete(&storage_key(NS_HOLD_REJOINED, group_id))
    }

    /// Set or drop [`NS_HOLD_REJOINED`] for `group_id`.
    pub(crate) fn set_hold_rejoined(&self, group_id: &[u8], rejoined: bool) -> Result<(), KvError> {
        let at = storage_key(NS_HOLD_REJOINED, group_id);
        if rejoined {
            return self.kv.put(&at, &[1]);
        }
        self.kv.delete(&at)
    }

    /// The highest epoch of the copy of `group_id` held now that the
    /// group's own head vouched for ([`NS_HEAD_VOUCHED`]).
    pub(crate) fn head_vouched(&self, group_id: &[u8]) -> Result<Option<u64>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_HEAD_VOUCHED, group_id))?
            .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
            .map(u64::from_be_bytes))
    }

    /// Record that the group's own head vouched for the copy of `group_id`
    /// at `epoch`: raises [`NS_HEAD_VOUCHED`], never lowers it.
    pub(crate) fn vouch_head_epoch(&self, group_id: &[u8], epoch: u64) -> Result<(), KvError> {
        if self.head_vouched(group_id)?.is_some_and(|at| at >= epoch) {
            return Ok(());
        }
        self.kv.put(
            &storage_key(NS_HEAD_VOUCHED, group_id),
            &epoch.to_be_bytes(),
        )
    }

    /// Set the steward key `group_id` counts in place of its meta's: `None`
    /// drops the record, so the meta's counts again.
    pub(crate) fn set_counted_steward(
        &self,
        group_id: &[u8],
        counted: Option<Option<&[u8; 32]>>,
    ) -> Result<(), KvError> {
        let at = storage_key(NS_COUNTED_STEWARD, group_id);
        match counted {
            None => self.kv.delete(&at),
            Some(None) => self.kv.put(&at, &[]),
            Some(Some(key)) => self.kv.put(&at, key),
        }
    }

    /// How many of this device's own commits in `group_id` were refused in
    /// a row ([`NS_OWN_COMMITS_REFUSED`]).
    pub(crate) fn own_commits_refused(&self, group_id: &[u8]) -> Result<u32, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_OWN_COMMITS_REFUSED, group_id))?
            .and_then(|bytes| <[u8; 4]>::try_from(bytes.as_slice()).ok())
            .map(u32::from_be_bytes)
            .unwrap_or(0))
    }

    /// Set the count of own commits refused in a row in `group_id`; zero
    /// drops the record.
    pub(crate) fn set_own_commits_refused(
        &self,
        group_id: &[u8],
        count: u32,
    ) -> Result<(), KvError> {
        let key = storage_key(NS_OWN_COMMITS_REFUSED, group_id);
        if count == 0 {
            return self.kv.delete(&key);
        }
        self.kv.put(&key, &count.to_be_bytes())
    }

    /// Drop what is kept about the copy of `group_id` held now, beside its
    /// head state: the join head, its verifiers, its envelope secrets, its
    /// refused-commit count.
    /// For a copy being deleted or replaced.
    pub(crate) fn forget_copy_records(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.forget_join_head(group_id)?;
        self.kv.delete(&storage_key(NS_COPY_VERIFIERS, group_id))?;
        self.kv.delete(&storage_key(NS_ENVELOPE_EPOCHS, group_id))?;
        self.kv.delete(&storage_key(NS_ENVELOPE_GAP, group_id))?;
        self.kv.delete(&storage_key(NS_STEWARD_KEYS, group_id))?;
        // A hold on record as its copy goes: the hold ended in a rejoin, and
        // stays counted so for the day (`NS_HOLD_REJOINED`).
        let held = self
            .kv
            .get(&storage_key(NS_GROUP_HOLD, group_id))?
            .is_some();
        if held && self.hold_started(group_id)?.is_some() {
            self.set_hold_rejoined(group_id, true)?;
        }
        self.kv.delete(&storage_key(NS_GROUP_HOLD, group_id))?;
        self.kv.delete(&storage_key(NS_HEAD_VOUCHED, group_id))?;
        self.kv.delete(&storage_key(NS_STAMP_STEWARD, group_id))?;
        self.kv.delete(&storage_key(NS_STAMPS_OPENED, group_id))?;
        self.kv.delete(&storage_key(NS_COUNTED_STEWARD, group_id))?;
        self.kv.delete(&storage_key(NS_HEAD_READ, group_id))?;
        self.set_own_commits_refused(group_id, 0)
    }

    /// The group state kept for `group_id` when this device forgot it
    /// ([`NS_REMEMBERED_POLICY`]).
    pub(crate) fn remembered_policy(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        self.kv.get(&storage_key(NS_REMEMBERED_POLICY, group_id))
    }

    /// Keep `meta` as the group state of the forgotten `group_id`.
    pub(crate) fn set_remembered_policy(
        &self,
        group_id: &[u8],
        meta: &[u8],
    ) -> Result<(), KvError> {
        self.kv
            .put(&storage_key(NS_REMEMBERED_POLICY, group_id), meta)
    }

    /// Drop the group state kept for `group_id`: the copy whose roster is
    /// kept now carried none.
    pub(crate) fn forget_remembered_policy(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(NS_REMEMBERED_POLICY, group_id))
    }

    /// The report-only roster kept for `group_id` ([`NS_REMEMBERED_UNVOUCHED`]);
    /// empty when none is kept, or the record does not read.
    pub(crate) fn remembered_unvouched(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<crate::group::RosterClaim>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_REMEMBERED_UNVOUCHED, group_id))?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default())
    }

    /// Keep `roster` as the report-only roster of `group_id`.
    pub(crate) fn set_remembered_unvouched(
        &self,
        group_id: &[u8],
        roster: &[crate::group::RosterClaim],
    ) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_REMEMBERED_UNVOUCHED, group_id),
            &serde_json::to_vec(roster)?,
        )
    }

    /// The epoch this device last proposed its leave of `group_id` at, when
    /// it is leaving the group ([`NS_LEAVING`]).
    pub(crate) fn leaving(&self, group_id: &[u8]) -> Result<Option<u64>, KvError> {
        let Some(bytes) = self.kv.get(&storage_key(NS_LEAVING, group_id))? else {
            return Ok(None);
        };
        // A record of another length is still a leave: only its epoch is
        // unknown, and zero proposes again at the next commit.
        Ok(Some(
            <[u8; 8]>::try_from(bytes.as_slice())
                .map(u64::from_be_bytes)
                .unwrap_or(0),
        ))
    }

    /// Record that this device is leaving `group_id`, having proposed it at
    /// `epoch`.
    pub(crate) fn set_leaving(&self, group_id: &[u8], epoch: u64) -> Result<(), KvError> {
        self.kv
            .put(&storage_key(NS_LEAVING, group_id), &epoch.to_be_bytes())
    }

    /// Drop the leaving record of `group_id`.
    pub(crate) fn forget_leaving(&self, group_id: &[u8]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(NS_LEAVING, group_id))
    }

    /// Keep `message`, a leave taken in at `epoch` under `reference`, for a
    /// commit to carry ([`NS_CARRIED_LEAVE`]); those of other epochs go.
    pub(crate) fn note_carried_leave(
        &self,
        group_id: &[u8],
        epoch: u64,
        reference: &[u8],
        message: &[u8],
    ) -> Result<(), KvError> {
        let prefix = storage_key(NS_CARRIED_LEAVE, &carried_leave_key(group_id, &[]));
        for (key, value) in self.kv.scan(&prefix)? {
            let at = value.first_chunk::<8>().map(|raw| u64::from_be_bytes(*raw));
            if at != Some(epoch) {
                self.kv.delete(&key)?;
            }
        }
        let mut value = Vec::with_capacity(8 + message.len());
        value.extend_from_slice(&epoch.to_be_bytes());
        value.extend_from_slice(message);
        self.kv.put(
            &storage_key(NS_CARRIED_LEAVE, &carried_leave_key(group_id, reference)),
            &value,
        )
    }

    /// The leave kept under `reference` in `group_id`, when it was taken at
    /// `epoch`.
    pub(crate) fn carried_leave(
        &self,
        group_id: &[u8],
        epoch: u64,
        reference: &[u8],
    ) -> Result<Option<Vec<u8>>, KvError> {
        let Some(value) = self.kv.get(&storage_key(
            NS_CARRIED_LEAVE,
            &carried_leave_key(group_id, reference),
        ))?
        else {
            return Ok(None);
        };
        Ok(match value.split_first_chunk::<8>() {
            Some((at, message)) if u64::from_be_bytes(*at) == epoch && !message.is_empty() => {
                Some(message.to_vec())
            }
            _ => None,
        })
    }

    /// Drop every leave kept for `group_id`.
    pub(crate) fn forget_carried_leaves(&self, group_id: &[u8]) -> Result<(), KvError> {
        let prefix = storage_key(NS_CARRIED_LEAVE, &carried_leave_key(group_id, &[]));
        for (key, _) in self.kv.scan(&prefix)? {
            self.kv.delete(&key)?;
        }
        Ok(())
    }

    /// Raise the epoch mark of `group_id` to `epoch`; a no-op when it is
    /// already at or above it.
    pub(crate) fn raise_epoch_mark(&self, group_id: &[u8], epoch: u64) -> Result<(), KvError> {
        if self.epoch_mark(group_id)?.is_some_and(|mark| mark >= epoch) {
            return Ok(());
        }
        self.kv
            .put(&storage_key(NS_EPOCH_MARK, group_id), &epoch.to_be_bytes())
    }

    /// Whether a Welcome under this key ([`welcome_taken_key`], or a stored
    /// digest of the whole Welcome) was taken through a last-resort
    /// package ([`NS_WELCOME_TAKEN`]).
    pub(crate) fn welcome_taken(&self, digest: &[u8]) -> Result<bool, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_WELCOME_TAKEN, digest))?
            .is_some())
    }

    /// Record a Welcome taken through the last-resort package `key_package_ref`.
    pub(crate) fn note_welcome_taken(
        &self,
        digest: &[u8],
        key_package_ref: &[u8],
    ) -> Result<(), KvError> {
        self.kv
            .put(&storage_key(NS_WELCOME_TAKEN, digest), key_package_ref)
    }

    /// Drop every record of a Welcome taken through `key_package_ref`.
    pub(crate) fn forget_welcomes_taken_with(&self, key_package_ref: &[u8]) -> Result<(), KvError> {
        for (key, value) in self.kv.scan(&namespace_prefix(NS_WELCOME_TAKEN))? {
            if value.as_slice() == key_package_ref {
                self.kv.delete(&key)?;
            }
        }
        Ok(())
    }

    /// Whether a seat ask under `key` (group digest, nonce, signature) is already
    /// recorded.
    pub fn join_request_seen(&self, key: &[u8]) -> Result<bool, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_JOIN_REQUEST_SEEN, key))?
            .is_some())
    }

    /// Record a seat ask under `key`, signed at `issued_at`.
    pub fn note_join_request(&self, key: &[u8], issued_at: i64) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_JOIN_REQUEST_SEEN, key),
            &issued_at.to_be_bytes(),
        )
    }

    /// Drop every recorded seat ask signed before `cutoff` (Unix seconds),
    /// and any record this build did not write.
    pub fn prune_join_requests(&self, cutoff: i64) -> Result<(), KvError> {
        for (key, value) in self.kv.scan(&namespace_prefix(NS_JOIN_REQUEST_SEEN))? {
            let keep = <[u8; 8]>::try_from(value.as_slice())
                .map(|at| i64::from_be_bytes(at) >= cutoff)
                .unwrap_or(false);
            if !keep {
                self.kv.delete(&key)?;
            }
        }
        Ok(())
    }

    /// Remember `device_id`, with `signing_key`, as the device that let this
    /// one in.
    pub fn set_own_approver(&self, device_id: &str, signing_key: &[u8]) -> Result<(), KvError> {
        self.kv.put(
            &storage_key(NS_OWN_APPROVER, device_id.as_bytes()),
            signing_key,
        )
    }

    /// Every device remembered as having let this one in: `(device_id,
    /// signing_key)`. A record this build did not write is skipped.
    pub fn own_approvers(&self) -> Result<Vec<(String, Vec<u8>)>, KvError> {
        let prefix = namespace_prefix(NS_OWN_APPROVER);
        Ok(self
            .kv
            .scan(&prefix)?
            .into_iter()
            .filter_map(|(key, value)| {
                let id = String::from_utf8(key.get(prefix.len()..)?.to_vec()).ok()?;
                (value.len() == 32 && !id.is_empty()).then(|| (id, value.to_vec()))
            })
            .collect())
    }

    /// Pin `twin_of` as the row `device_id` is linked to, unless a link is
    /// already pinned for it. Answers whether it wrote.
    pub fn note_own_install_link(&self, device_id: &str, twin_of: &str) -> Result<bool, KvError> {
        let key = storage_key(NS_OWN_INSTALL_LINK, device_id.as_bytes());
        if self.kv.get(&key)?.is_some() {
            return Ok(false);
        }
        self.kv.put(&key, twin_of.as_bytes())?;
        Ok(true)
    }

    /// Keep `keys` as what the restore at `restored_since` signed out, unless
    /// a snapshot is already kept for it. Answers whether it wrote.
    pub fn note_restore_snapshot(
        &self,
        restored_since: i64,
        keys: &[String],
    ) -> Result<bool, KvError> {
        let key = storage_key(NS_RESTORE_SNAPSHOT, &restored_since.to_be_bytes());
        if self.kv.get(&key)?.is_some() {
            return Ok(false);
        }
        self.kv.put(&key, &serde_json::to_vec(keys)?)?;
        Ok(true)
    }

    /// The snapshot [`Self::note_restore_snapshot`] kept for the restore at
    /// `restored_since`, or `None` while none is kept.
    pub fn restore_snapshot(&self, restored_since: i64) -> Result<Option<Vec<String>>, KvError> {
        match self.kv.get(&storage_key(
            NS_RESTORE_SNAPSHOT,
            &restored_since.to_be_bytes(),
        ))? {
            Some(value) => Ok(Some(serde_json::from_slice(&value)?)),
            None => Ok(None),
        }
    }

    /// Record `device_key` as one whose revocation this device signed, or
    /// took as signed out from a restore's answer.
    pub fn note_own_key_signed_out(&self, device_key: &[u8]) -> Result<(), KvError> {
        self.kv
            .put(&storage_key(NS_OWN_KEY_SIGNED_OUT, device_key), &[])
    }

    /// Whether [`Self::note_own_key_signed_out`] recorded `device_key`.
    pub fn own_key_signed_out(&self, device_key: &[u8]) -> Result<bool, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_OWN_KEY_SIGNED_OUT, device_key))?
            .is_some())
    }

    /// Keep the account's `signature` revoking `device_key`, verified by the
    /// caller, with `revoked_at`, the second the delivery service said it
    /// took effect (`0` for unknown). Replaces what was kept: the caller
    /// decides which time stands ([`crate::group::Client::stale_leaf_removable`]).
    pub fn note_peer_revocation(
        &self,
        device_key: &[u8],
        signature: &[u8],
        revoked_at: i64,
    ) -> Result<(), KvError> {
        let mut value = Vec::with_capacity(signature.len() + 8);
        value.extend_from_slice(signature);
        value.extend_from_slice(&revoked_at.to_be_bytes());
        self.kv
            .put(&storage_key(NS_PEER_REVOKED, device_key), &value)
    }

    /// The revocation [`Self::note_peer_revocation`] kept for `device_key`:
    /// its signature and the second it took effect (`0` for unknown).
    pub fn peer_revocation(&self, device_key: &[u8]) -> Result<Option<(Vec<u8>, i64)>, KvError> {
        let Some(mut value) = self.kv.get(&storage_key(NS_PEER_REVOKED, device_key))? else {
            return Ok(None);
        };
        let Some(split) = value.len().checked_sub(8) else {
            return Ok(Some((value, 0)));
        };
        let mut time = [0u8; 8];
        time.copy_from_slice(&value[split..]);
        value.truncate(split);
        Ok(Some((value, i64::from_be_bytes(time))))
    }

    /// The row [`Self::note_own_install_link`] pinned for `device_id`.
    pub fn own_install_link(&self, device_id: &str) -> Result<Option<String>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_OWN_INSTALL_LINK, device_id.as_bytes()))?
            .and_then(|value| String::from_utf8(value).ok()))
    }

    /// Stop remembering `device_id` as the device that let this one in.
    pub fn forget_own_approver(&self, device_id: &str) -> Result<(), KvError> {
        self.kv
            .delete(&storage_key(NS_OWN_APPROVER, device_id.as_bytes()))
    }

    /// Record `device_id`, a device of this account, as removed.
    pub fn note_own_device_forgotten(&self, device_id: &str) -> Result<(), KvError> {
        self.kv
            .put(&storage_key(NS_OWN_FORGOTTEN, device_id.as_bytes()), &[1])
    }

    /// Whether `device_id` was recorded as removed.
    pub fn own_device_forgotten(&self, device_id: &str) -> Result<bool, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_OWN_FORGOTTEN, device_id.as_bytes()))?
            .is_some())
    }

    /// Every device id recorded as removed.
    pub fn forgotten_own_devices(&self) -> Result<Vec<String>, KvError> {
        let prefix = namespace_prefix(NS_OWN_FORGOTTEN);
        Ok(self
            .kv
            .scan(&prefix)?
            .into_iter()
            .filter_map(|(key, _)| String::from_utf8(key.get(prefix.len()..)?.to_vec()).ok())
            .filter(|id| !id.is_empty())
            .collect())
    }

    /// Record `device_key`, seen held by `device_id`, a forgotten device of
    /// this account, as forgotten too. Answers whether it was not already.
    pub fn note_own_key_forgotten(
        &self,
        device_key: &[u8],
        device_id: &str,
    ) -> Result<bool, KvError> {
        let key = storage_key(NS_OWN_FORGOTTEN_KEY, device_key);
        if self.kv.get(&key)?.is_some() {
            return Ok(false);
        }
        self.kv.put(&key, device_id.as_bytes())?;
        Ok(true)
    }

    /// Every device key recorded by [`Self::note_own_key_forgotten`]. A
    /// record this build did not write is skipped.
    pub fn forgotten_own_keys(&self) -> Result<Vec<Vec<u8>>, KvError> {
        let prefix = namespace_prefix(NS_OWN_FORGOTTEN_KEY);
        Ok(self
            .kv
            .scan(&prefix)?
            .into_iter()
            .filter_map(|(key, _)| {
                let rest = key.get(prefix.len()..)?;
                (rest.len() == 32).then(|| rest.to_vec())
            })
            .collect())
    }

    fn own_seat_vouched_key(device_id: &str, device_key: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(device_key.len() + device_id.len());
        key.extend_from_slice(device_key);
        key.extend_from_slice(device_id.as_bytes());
        storage_key(NS_OWN_SEAT_VOUCHED, &key)
    }

    /// Record that the own-device check answered a seating verdict for
    /// `device_id` under `device_key`. Answers whether it wrote.
    pub fn note_own_seat_vouched(
        &self,
        device_id: &str,
        device_key: &[u8],
    ) -> Result<bool, KvError> {
        let key = Self::own_seat_vouched_key(device_id, device_key);
        if self.kv.get(&key)?.is_some() {
            return Ok(false);
        }
        self.kv.put(&key, &[1])?;
        Ok(true)
    }

    /// Whether [`Self::note_own_seat_vouched`] recorded the pair.
    pub fn own_seat_vouched(&self, device_id: &str, device_key: &[u8]) -> Result<bool, KvError> {
        Ok(self
            .kv
            .get(&Self::own_seat_vouched_key(device_id, device_key))?
            .is_some())
    }

    fn own_vouched_key(device_id: &str, device_key: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(device_key.len() + device_id.len());
        key.extend_from_slice(device_key);
        key.extend_from_slice(device_id.as_bytes());
        storage_key(NS_OWN_VOUCHED, &key)
    }

    /// Record `device_id` under the raw 32-byte `device_key` as a device of
    /// this account on the approval chain, vouched for by the device whose
    /// raw 32-byte key `approver_key` its approval verified under. A pair
    /// already recorded gains the approver if it is new, and a record of the
    /// old one-byte form (written before approvers were kept) is replaced.
    /// Answers whether it wrote.
    pub fn note_own_vouched(
        &self,
        device_id: &str,
        device_key: &[u8],
        approver_key: &[u8],
    ) -> Result<bool, KvError> {
        let key = Self::own_vouched_key(device_id, device_key);
        let mut value = match self.kv.get(&key)? {
            Some(value) if value.len() % 32 == 0 => value,
            _ => Vec::new(),
        };
        if value.chunks(32).any(|known| known == approver_key) {
            return Ok(false);
        }
        value.extend_from_slice(approver_key);
        self.kv.put(&key, &value)?;
        Ok(true)
    }

    /// Every pair [`Self::note_own_vouched`] recorded, with the keys of the
    /// devices that vouched for it: `None` for a record written before
    /// approvers were kept. A record this build did not write is skipped.
    pub fn own_vouched_by(&self) -> Result<Vec<OwnVouched>, KvError> {
        let prefix = namespace_prefix(NS_OWN_VOUCHED);
        Ok(self
            .kv
            .scan(&prefix)?
            .into_iter()
            .filter_map(|(key, value)| {
                let rest = key.get(prefix.len()..)?;
                if rest.len() <= 32 {
                    return None;
                }
                let (device_key, id) = rest.split_at(32);
                let id = String::from_utf8(id.to_vec()).ok()?;
                let approvers = if *value == [1] {
                    None
                } else if !value.is_empty() && value.len() % 32 == 0 {
                    Some(value.chunks(32).map(<[u8]>::to_vec).collect())
                } else {
                    return None;
                };
                Some(((id, device_key.to_vec()), approvers))
            })
            .collect())
    }

    /// Every `(device_id, device_key)` recorded by [`Self::note_own_vouched`].
    /// A record this build did not write is skipped.
    pub fn own_vouched(&self) -> Result<Vec<(String, Vec<u8>)>, KvError> {
        let prefix = namespace_prefix(NS_OWN_VOUCHED);
        Ok(self
            .kv
            .scan(&prefix)?
            .into_iter()
            .filter_map(|(key, _)| {
                let rest = key.get(prefix.len()..)?;
                if rest.len() <= 32 {
                    return None;
                }
                let (device_key, id) = rest.split_at(32);
                let id = String::from_utf8(id.to_vec()).ok()?;
                Some((id, device_key.to_vec()))
            })
            .collect())
    }

    fn own_unvouched_key(device_id: &str, device_key: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(device_key.len() + device_id.len());
        key.extend_from_slice(device_key);
        key.extend_from_slice(device_id.as_bytes());
        storage_key(NS_OWN_UNVOUCHED, &key)
    }

    /// Record a leaf of this account, `device_id` under the raw 32-byte
    /// `device_key`, as seated by a committer this device does not trust.
    pub fn note_own_unvouched(&self, device_id: &str, device_key: &[u8]) -> Result<(), KvError> {
        self.kv
            .put(&Self::own_unvouched_key(device_id, device_key), &[1])
    }

    /// Drop the record [`Self::note_own_unvouched`] made, if any. Answers
    /// whether there was one.
    pub fn clear_own_unvouched(&self, device_id: &str, device_key: &[u8]) -> Result<bool, KvError> {
        let key = Self::own_unvouched_key(device_id, device_key);
        if self.kv.get(&key)?.is_none() {
            return Ok(false);
        }
        self.kv.delete(&key)?;
        Ok(true)
    }

    /// Every `(device_id, device_key)` recorded by [`Self::note_own_unvouched`].
    /// A record this build did not write is skipped.
    pub fn own_unvouched(&self) -> Result<Vec<(String, Vec<u8>)>, KvError> {
        let prefix = namespace_prefix(NS_OWN_UNVOUCHED);
        Ok(self
            .kv
            .scan(&prefix)?
            .into_iter()
            .filter_map(|(key, _)| {
                let rest = key.get(prefix.len()..)?;
                if rest.len() <= 32 {
                    return None;
                }
                let (device_key, id) = rest.split_at(32);
                let id = String::from_utf8(id.to_vec()).ok()?;
                Some((id, device_key.to_vec()))
            })
            .collect())
    }

    /// Record `device_key` as the key `device_id`, another device of this
    /// account, was first seen holding in a tree, unless a key is recorded
    /// for it already. Answers whether it wrote. Stored as the bare 32-byte
    /// key, the one format every build reads.
    pub fn note_own_sibling_key(
        &self,
        device_id: &str,
        device_key: &[u8],
    ) -> Result<bool, KvError> {
        let key = storage_key(NS_OWN_SIBLING_KEY, device_id.as_bytes());
        if self.kv.get(&key)?.is_some() {
            return Ok(false);
        }
        self.kv.put(&key, device_key)?;
        Ok(true)
    }

    /// Record `device_key` as the key `device_id`, another device of this
    /// account, holds ON EVIDENCE: an approval this device checked, or this
    /// device's own add of it. Replaces a key recorded from a tree
    /// ([`Self::note_own_sibling_key`]); never another evidence record.
    /// Answers whether it wrote. Stored as the key then one marker byte
    /// (`SIBLING_KEY_EVIDENCE`): a build that reads only the bare form takes
    /// such a record as none, and since it never overwrites a record, it
    /// leaves it in place.
    pub fn note_own_sibling_key_evidence(
        &self,
        device_id: &str,
        device_key: &[u8],
    ) -> Result<bool, KvError> {
        let key = storage_key(NS_OWN_SIBLING_KEY, device_id.as_bytes());
        if let Some(held) = self.kv.get(&key)? {
            if held.len() == 33 && held[32] == SIBLING_KEY_EVIDENCE {
                return Ok(false);
            }
        }
        let mut value = Vec::with_capacity(device_key.len() + 1);
        value.extend_from_slice(device_key);
        value.push(SIBLING_KEY_EVIDENCE);
        self.kv.put(&key, &value)?;
        Ok(true)
    }

    /// The key recorded for `device_id` by [`Self::note_own_sibling_key`]
    /// or [`Self::note_own_sibling_key_evidence`]. A record this build did
    /// not write reads as none.
    pub fn own_sibling_key(&self, device_id: &str) -> Result<Option<Vec<u8>>, KvError> {
        Ok(self
            .kv
            .get(&storage_key(NS_OWN_SIBLING_KEY, device_id.as_bytes()))?
            .and_then(|mut key| match key.len() {
                32 => Some(key),
                33 if key[32] == SIBLING_KEY_EVIDENCE => {
                    key.truncate(32);
                    Some(key)
                }
                _ => None,
            }))
    }

    /// Every group id this device has state for, in key order.
    pub fn remembered_group_ids(&self) -> Result<Vec<Vec<u8>>, KvError> {
        Ok(self
            .kv
            .scan(&namespace_prefix(NS_GROUP_INDEX))?
            .into_iter()
            .map(|(_, value)| value.to_vec())
            .collect())
    }

    // ---- Internals ----------------------------------------------------------

    /// OpenMLS's state is its secrets (epoch secrets, ratchet keys, private
    /// keys), so every value this glue writes and reads is wiped: written in a
    /// buffer sized before the first byte ([`json_unspilled`]) and wiped once
    /// the store has it, and read back into one wiped once it is decoded.
    fn write<V: serde::Serialize + ?Sized>(
        &self,
        namespace: &[u8],
        key: &[u8],
        value: &V,
    ) -> Result<(), KvError> {
        let value = json_unspilled(value)?;
        self.kv.put(&storage_key(namespace, key), &value)
    }

    fn read<V: Entity<CURRENT_VERSION>>(
        &self,
        namespace: &[u8],
        key: &[u8],
    ) -> Result<Option<V>, KvError> {
        match self.kv.get(&storage_key(namespace, key))? {
            Some(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                Ok(Some(self.kv.decoded(serde_json::from_slice(&bytes))?))
            }
            None => Ok(None),
        }
    }

    fn erase(&self, namespace: &[u8], key: &[u8]) -> Result<(), KvError> {
        self.kv.delete(&storage_key(namespace, key))
    }

    /// A list lives as ONE value holding a JSON array of already-serialised
    /// elements, exactly as OpenMLS' own in-memory provider keeps it.
    ///
    /// The alternative — one key per element under a shared prefix, read back
    /// with `scan` — reads better and is wrong here: appending would need a
    /// monotonic counter per list to preserve order, and `remove_item` would
    /// need to find an element by its bytes across a scan. A list of queued
    /// proposals is short and rewritten whole either way.
    fn append<V: serde::Serialize + ?Sized>(
        &self,
        namespace: &[u8],
        key: &[u8],
        value: &V,
    ) -> Result<(), KvError> {
        let mut list = self.read_raw_list(namespace, key)?;
        let mut value = json_unspilled(value)?;
        // A reallocation of the list moves each element's pointer, never
        // its bytes.
        list.push(std::mem::take(&mut *value));
        self.write(namespace, key, &*list)
    }

    fn remove_item<V: serde::Serialize + ?Sized>(
        &self,
        namespace: &[u8],
        key: &[u8],
        value: &V,
    ) -> Result<(), KvError> {
        let mut list = self.read_raw_list(namespace, key)?;
        let value = json_unspilled(value)?;
        if let Some(at) = list.iter().position(|item| item[..] == value[..]) {
            // Wiped as it goes; the elements after it move by pointer.
            zeroize::Zeroize::zeroize(&mut list.remove(at));
        }
        self.write(namespace, key, &*list)
    }

    /// A list's elements, each wiped when the list drops.
    fn read_raw_list(
        &self,
        namespace: &[u8],
        key: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<Vec<u8>>>, KvError> {
        match self.kv.get(&storage_key(namespace, key))? {
            Some(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                let elements: Vec<WipedBytes> = self.kv.decoded(serde_json::from_slice(&bytes))?;
                Ok(zeroize::Zeroizing::new(
                    elements
                        .into_iter()
                        .map(|mut element| std::mem::take(&mut *element.0))
                        .collect(),
                ))
            }
            None => Ok(zeroize::Zeroizing::new(Vec::new())),
        }
    }

    fn read_list<V: Entity<CURRENT_VERSION>>(
        &self,
        namespace: &[u8],
        key: &[u8],
    ) -> Result<Vec<V>, KvError> {
        self.read_raw_list(namespace, key)?
            .iter()
            .map(|bytes| self.kv.decoded(serde_json::from_slice(bytes)))
            .collect()
    }
}

/// One element of a stored list (a JSON array of bytes), read into a buffer
/// that wipes itself, and that wipes the smaller one it outgrows: serde's own
/// `Vec<u8>` grows by reallocation, leaving each smaller buffer's bytes in
/// the block it frees.
struct WipedBytes(zeroize::Zeroizing<Vec<u8>>);

impl<'de> serde::Deserialize<'de> for WipedBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = WipedBytes;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an array of bytes")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<WipedBytes, A::Error> {
                let mut out = zeroize::Zeroizing::new(Vec::with_capacity(
                    seq.size_hint().unwrap_or(0).min(1 << 16),
                ));
                while let Some(byte) = seq.next_element::<u8>()? {
                    if out.len() == out.capacity() {
                        let mut grown = zeroize::Zeroizing::new(Vec::with_capacity(
                            out.capacity().saturating_mul(2).max(64),
                        ));
                        grown.extend_from_slice(&out);
                        // The smaller buffer is wiped as it drops here.
                        out = grown;
                    }
                    out.push(byte);
                }
                Ok(WipedBytes(out))
            }
        }
        deserializer.deserialize_seq(Visitor)
    }
}

/// `value` as JSON in a buffer sized before the first byte is written, so no
/// reallocation leaves a copy of what it holds behind (the length is counted
/// in a first pass that writes nothing), wiped when it drops.
pub(crate) fn json_unspilled<V: serde::Serialize + ?Sized>(
    value: &V,
) -> serde_json::Result<zeroize::Zeroizing<Vec<u8>>> {
    struct Counting(usize);
    impl std::io::Write for Counting {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counting = Counting(0);
    serde_json::to_writer(&mut counting, value)?;
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(counting.0));
    serde_json::to_writer(&mut *out, value)?;
    Ok(out)
}

/// `len(group_id) as u32 BE || group_id || actor_id`: length-prefixed so one
/// group id can never be read as the prefix of another.
/// The key a [`NS_CARRIED_LEAVE`] record lives under: the group id with its
/// length, then the proposal reference.
fn carried_leave_key(group_id: &[u8], reference: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + group_id.len() + reference.len());
    key.extend_from_slice(
        &u32::try_from(group_id.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    key.extend_from_slice(group_id);
    key.extend_from_slice(reference);
    key
}

/// The key an [`NS_OPENED`] record lives under: the group id with its
/// length, then the message's digest (empty for the group's prefix).
fn opened_key(group_id: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + group_id.len() + digest.len());
    key.extend_from_slice(
        &u32::try_from(group_id.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    key.extend_from_slice(group_id);
    key.extend_from_slice(digest);
    key
}

/// 32-byte digests stored concatenated, sorted and deduplicated.
fn read_digests(stored: Option<Vec<u8>>) -> Vec<[u8; 32]> {
    let stored = stored.unwrap_or_default();
    let mut digests: Vec<[u8; 32]> = stored.as_chunks::<32>().0.to_vec();
    digests.sort_unstable();
    digests.dedup();
    digests
}

/// `digests` as [`read_digests`] reads them back.
fn sorted_digests(digests: &[[u8; 32]]) -> Vec<u8> {
    let mut sorted = digests.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    sorted.concat()
}

fn account_seen_key(group_id: &[u8], actor_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + group_id.len() + actor_id.len());
    key.extend_from_slice(
        &u32::try_from(group_id.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    key.extend_from_slice(group_id);
    key.extend_from_slice(actor_id.as_bytes());
    key
}

/// The compound key an epoch's key pairs live under: group, epoch, leaf.
fn epoch_key_pairs_key(
    group_id: &impl traits::GroupId<CURRENT_VERSION>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> Result<Vec<u8>, KvError> {
    let mut key = serde_json::to_vec(group_id)?;
    key.extend_from_slice(&serde_json::to_vec(epoch)?);
    key.extend_from_slice(&serde_json::to_vec(&leaf_index)?);
    Ok(key)
}

/// The OpenMLS provider Peachy uses: RustCrypto for the primitives, Peachy's
/// own store for the state.
///
/// Was `OpenMlsRustCrypto` — which is exactly this pairing with
/// `MemoryStorage` in the second slot. The crypto half is unchanged and
/// deliberately so: `openmls_rust_crypto`'s RustCrypto is what the RFC 9420
/// vectors in `mls/core/tests/rfc9420_vectors.rs` are checked against.
#[derive(Debug)]
pub struct PeachyProvider {
    crypto: RustCrypto,
    storage: PeachyStorage,
}

impl PeachyProvider {
    pub fn new(storage: PeachyStorage) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage,
        }
    }

    /// A provider whose state dies with the process.
    pub fn ephemeral() -> Self {
        Self::new(PeachyStorage::in_memory())
    }

    /// The store, for the Peachy-side calls OpenMLS' trait does not have.
    pub fn peachy_storage(&self) -> &PeachyStorage {
        &self.storage
    }
}

impl Default for PeachyProvider {
    fn default() -> Self {
        Self::ephemeral()
    }
}

impl OpenMlsProvider for PeachyProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = PeachyStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

// ---- StorageProvider --------------------------------------------------------
//
// 53 methods, each one a namespace and a key. The shape mirrors OpenMLS' own
// in-memory provider method for method, on purpose: this is the implementation
// the protocol engine's tests were written against, and a clever divergence
// here would be a divergence nobody could see in a stack trace.

impl StorageProvider<CURRENT_VERSION> for PeachyStorage {
    type Error = KvError;

    // ---- group state: writers ----

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.write(NS_JOIN_CONFIG, &serde_json::to_vec(group_id)?, config)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        self.append(NS_OWN_LEAF_NODES, &serde_json::to_vec(group_id)?, leaf_node)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        self.write(
            NS_QUEUED_PROPOSAL,
            &serde_json::to_vec(&(group_id, proposal_ref))?,
            proposal,
        )?;
        self.append(
            NS_PROPOSAL_REFS,
            &serde_json::to_vec(group_id)?,
            proposal_ref,
        )
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write(NS_TREE, &serde_json::to_vec(group_id)?, tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.write(
            NS_INTERIM_TRANSCRIPT_HASH,
            &serde_json::to_vec(group_id)?,
            interim_transcript_hash,
        )
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.write(
            NS_GROUP_CONTEXT,
            &serde_json::to_vec(group_id)?,
            group_context,
        )
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.write(
            NS_CONFIRMATION_TAG,
            &serde_json::to_vec(group_id)?,
            confirmation_tag,
        )
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.write(NS_GROUP_STATE, &serde_json::to_vec(group_id)?, group_state)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write(
            NS_MESSAGE_SECRETS,
            &serde_json::to_vec(group_id)?,
            message_secrets,
        )
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write(
            NS_RESUMPTION_PSK,
            &serde_json::to_vec(group_id)?,
            resumption_psk_store,
        )
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.write(
            NS_OWN_LEAF_INDEX,
            &serde_json::to_vec(group_id)?,
            own_leaf_index,
        )
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write(
            NS_EPOCH_SECRETS,
            &serde_json::to_vec(group_id)?,
            group_epoch_secrets,
        )
    }

    // ---- crypto objects: writers ----

    /// REFUSED: this store keeps no signature key pair. The device's signer
    /// is built from the seed the platform key store hands in at every open
    /// ([`crate::group::Client::new`]) and lives only in memory; OpenMLS
    /// takes it as an argument to every operation and never looks one up.
    /// A write here would put the device's private key in the store a
    /// second time, so it is an error rather than a quiet no-op
    /// ([`PeachyStorage::erase_signature_key_pairs`] clears any key pair a
    /// store holds).
    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        _public_key: &SignaturePublicKey,
        _signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        Err(KvError::new(
            "this store keeps no signature key pair: the signer is built from the device seed at open",
        ))
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.write(
            NS_ENCRYPTION_KEY,
            &serde_json::to_vec(public_key)?,
            key_pair,
        )
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        // One value holding the whole slice, not a list blob: OpenMLS writes
        // and reads this one whole, and its getter deserialises a `Vec` in one
        // step rather than element by element.
        self.write(
            NS_EPOCH_KEY_PAIRS,
            &epoch_key_pairs_key(group_id, epoch, leaf_index)?,
            key_pairs,
        )
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        self.write(NS_KEY_PACKAGE, &serde_json::to_vec(hash_ref)?, key_package)
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.write(NS_PSK, &serde_json::to_vec(psk_id)?, psk)
    }

    // ---- group state: getters ----

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.read(NS_JOIN_CONFIG, &serde_json::to_vec(group_id)?)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.read_list(NS_OWN_LEAF_NODES, &serde_json::to_vec(group_id)?)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.read_list(NS_PROPOSAL_REFS, &serde_json::to_vec(group_id)?)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> =
            self.read_list(NS_PROPOSAL_REFS, &serde_json::to_vec(group_id)?)?;
        let mut out = Vec::with_capacity(refs.len());
        for proposal_ref in refs {
            let key = serde_json::to_vec(&(group_id, &proposal_ref))?;
            // A ref in the queue with no proposal behind it is a torn write,
            // and it is skipped rather than unwrapped into a panic — the queue
            // is advisory, and a proposal nobody can load is a proposal nobody
            // will commit. OpenMLS' own provider unwraps here.
            if let Some(proposal) = self.read(NS_QUEUED_PROPOSAL, &key)? {
                out.push((proposal_ref, proposal));
            }
        }
        Ok(out)
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.read(NS_TREE, &serde_json::to_vec(group_id)?)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.read(NS_GROUP_CONTEXT, &serde_json::to_vec(group_id)?)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.read(NS_INTERIM_TRANSCRIPT_HASH, &serde_json::to_vec(group_id)?)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.read(NS_CONFIRMATION_TAG, &serde_json::to_vec(group_id)?)
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.read(NS_GROUP_STATE, &serde_json::to_vec(group_id)?)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.read(NS_MESSAGE_SECRETS, &serde_json::to_vec(group_id)?)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.read(NS_RESUMPTION_PSK, &serde_json::to_vec(group_id)?)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.read(NS_OWN_LEAF_INDEX, &serde_json::to_vec(group_id)?)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.read(NS_EPOCH_SECRETS, &serde_json::to_vec(group_id)?)
    }

    // ---- crypto objects: getters ----

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        self.read(NS_SIGNATURE_KEY, &serde_json::to_vec(public_key)?)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.read(NS_ENCRYPTION_KEY, &serde_json::to_vec(public_key)?)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let key = epoch_key_pairs_key(group_id, epoch, leaf_index)?;
        match self.kv.get(&storage_key(NS_EPOCH_KEY_PAIRS, &key))? {
            // The stored JSON spells the HPKE private keys: wiped once decoded.
            Some(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                self.kv.decoded(serde_json::from_slice(&bytes))
            }
            None => Ok(Vec::new()),
        }
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.read(NS_KEY_PACKAGE, &serde_json::to_vec(hash_ref)?)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.read(NS_PSK, &serde_json::to_vec(psk_id)?)
    }

    // ---- group state: deleters ----

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        self.remove_item(
            NS_PROPOSAL_REFS,
            &serde_json::to_vec(group_id)?,
            proposal_ref,
        )?;
        self.erase(
            NS_QUEUED_PROPOSAL,
            &serde_json::to_vec(&(group_id, proposal_ref))?,
        )
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.erase(NS_OWN_LEAF_NODES, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.erase(NS_JOIN_CONFIG, &serde_json::to_vec(group_id)?)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.erase(NS_TREE, &serde_json::to_vec(group_id)?)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.erase(NS_CONFIRMATION_TAG, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.erase(NS_GROUP_STATE, &serde_json::to_vec(group_id)?)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.erase(NS_GROUP_CONTEXT, &serde_json::to_vec(group_id)?)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.erase(NS_INTERIM_TRANSCRIPT_HASH, &serde_json::to_vec(group_id)?)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.erase(NS_MESSAGE_SECRETS, &serde_json::to_vec(group_id)?)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.erase(NS_RESUMPTION_PSK, &serde_json::to_vec(group_id)?)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.erase(NS_OWN_LEAF_INDEX, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.erase(NS_EPOCH_SECRETS, &serde_json::to_vec(group_id)?)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group_key = serde_json::to_vec(group_id)?;
        let refs: Vec<ProposalRef> = self.read_list(NS_PROPOSAL_REFS, &group_key)?;
        for proposal_ref in refs {
            self.erase(
                NS_QUEUED_PROPOSAL,
                &serde_json::to_vec(&(group_id, &proposal_ref))?,
            )?;
        }
        self.erase(NS_PROPOSAL_REFS, &group_key)
    }

    // ---- crypto objects: deleters ----

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.erase(NS_SIGNATURE_KEY, &serde_json::to_vec(public_key)?)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.erase(NS_ENCRYPTION_KEY, &serde_json::to_vec(public_key)?)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        self.erase(
            NS_EPOCH_KEY_PAIRS,
            &epoch_key_pairs_key(group_id, epoch, leaf_index)?,
        )
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.erase(NS_KEY_PACKAGE, &serde_json::to_vec(hash_ref)?)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.erase(NS_PSK, &serde_json::to_vec(psk_id)?)
    }
}

#[cfg(test)]
// As `fixture.rs`: the crate denies `expect` for the LIBRARY, and a test that
// cannot proceed should stop on the line that failed.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_leaf_people_record_of_another_version_does_not_read() {
        let people = LeafPeople {
            forgotten_at_ms: 7,
            people: vec![LeafPerson {
                key: [3; 32],
                left_epoch: 4,
                left_at_ms: 5,
                actor_id: "actor-cy".into(),
            }],
        };
        let mut raw = people.encode();
        assert_eq!(raw.first(), Some(&LEAF_PEOPLE_VERSION));
        assert_eq!(LeafPeople::decode(&raw), Some(people));
        raw[0] = LEAF_PEOPLE_VERSION + 1;
        assert_eq!(LeafPeople::decode(&raw), None);
        assert_eq!(LeafPeople::decode(&[]), None);
    }

    #[test]
    fn a_time_left_ahead_of_the_clock_is_set_to_now() {
        let mut people = LeafPeople {
            forgotten_at_ms: 0,
            people: vec![
                LeafPerson {
                    key: [1; 32],
                    left_epoch: 2,
                    left_at_ms: 500,
                    actor_id: "a".into(),
                },
                LeafPerson {
                    key: [2; 32],
                    left_epoch: 2,
                    left_at_ms: 90,
                    actor_id: "b".into(),
                },
            ],
        };
        assert!(people.clamp_left_at(100));
        assert_eq!(people.people[0].left_at_ms, 100);
        assert_eq!(people.people[1].left_at_ms, 90);
        assert!(!people.clamp_left_at(100));
        people.forgotten_at_ms = 400;
        assert!(people.clamp_left_at(100));
        assert_eq!(people.forgotten_at_ms, 100);
        assert!(!people.clamp_left_at(100));
    }

    #[test]
    fn a_key_carries_its_version_and_namespace() {
        let key = storage_key(NS_TREE, b"[1,2,3]");
        assert_eq!(key.first(), Some(&STORAGE_SCHEMA_VERSION));
        assert!(key.starts_with(&namespace_prefix(NS_TREE)));
        assert!(key.starts_with(&schema_prefix()));
    }

    /// `tree` is a prefix of no other namespace, but the guard has to hold for
    /// the pair that IS a prefix relationship, or a scan of one namespace would
    /// return rows from another.
    #[test]
    fn a_namespace_scan_does_not_spill_into_a_longer_name() {
        let kv = MemoryKv::new();
        // `psk` is a prefix of nothing here; `group` IS a prefix of nothing
        // either, so the case is built rather than found.
        kv.put(&storage_key(b"ab", b"one"), b"1").expect("put");
        kv.put(&storage_key(b"abc", b"two"), b"2").expect("put");
        let found = kv.scan(&namespace_prefix(b"ab")).expect("scan");
        assert_eq!(found.len(), 1, "the separator must end the namespace");
    }

    /// A member driving commits fast in an enrolled group cannot grow the
    /// kept steward keys past the verifier window, whatever the clock says.
    #[test]
    fn the_kept_steward_keys_are_capped_by_count() {
        let store = PeachyStorage::open(Box::new(MemoryKv::new())).expect("open");
        let total = COPY_VERIFIERS_KEPT as u64 * 4;
        for epoch in 1..=total {
            store
                .note_steward_key(b"g", epoch, 1_000, &[7; 32])
                .expect("note");
        }
        let kept = store.steward_keys(b"g").expect("read");
        assert_eq!(kept.len(), COPY_VERIFIERS_KEPT + 1);
        assert_eq!(
            kept.first().map(|(at, _, _)| *at),
            Some(total - COPY_VERIFIERS_KEPT as u64)
        );
        assert_eq!(kept.last().map(|(at, _, _)| *at), Some(total));
    }

    #[test]
    fn the_group_index_survives_a_reopen() {
        let kv = MemoryKv::new();
        {
            let store = PeachyStorage::open(Box::new(kv.clone())).expect("open");
            store.remember_group(b"alpha").expect("remember");
            store.remember_group(b"beta").expect("remember");
            store.flush().expect("flush");
        }
        let store = PeachyStorage::open(Box::new(kv)).expect("reopen");
        assert_eq!(
            store.remembered_group_ids().expect("ids"),
            vec![b"alpha".to_vec(), b"beta".to_vec()]
        );
        store.forget_group(b"alpha").expect("forget");
        assert_eq!(
            store.remembered_group_ids().expect("ids"),
            vec![b"beta".to_vec()]
        );
    }

    #[test]
    fn a_future_schema_is_refused_rather_than_read() {
        let kv = MemoryKv::new();
        kv.put(&storage_key(NS_META, META_SCHEMA), &[9])
            .expect("put");
        let error = PeachyStorage::open(Box::new(kv)).expect_err("a version 9 store must refuse");
        assert!(error.to_string().contains("schema version 9"));
    }

    /// The other half of the asymmetry: an OLDER store opens. Refusing every
    /// version but this one would brick every existing device on the release
    /// that bumps the number — for a store the new code cannot misread,
    /// because the old rows are under a version byte it never scans.
    #[test]
    fn an_older_schema_opens_and_is_restamped() {
        let kv = MemoryKv::new();
        let stamp_key = storage_key(NS_META, META_SCHEMA);
        kv.put(&stamp_key, &[STORAGE_SCHEMA_VERSION - 1])
            .expect("put");
        // A row from that older schema, under its own version byte.
        let mut old_row = vec![STORAGE_SCHEMA_VERSION - 1];
        old_row.extend_from_slice(b"group\x1fancient");
        kv.put(&old_row, b"whatever the old layout meant")
            .expect("put");

        let store = PeachyStorage::open(Box::new(kv)).expect("an older store must open");

        // Re-stamped, so the stamp always names the newest schema that has
        // written here — the invariant a future migration reads.
        assert_eq!(
            store.kv.get(&stamp_key).expect("get"),
            Some(vec![STORAGE_SCHEMA_VERSION])
        );
        // And the older rows are invisible rather than misread.
        assert!(store
            .kv
            .scan(&schema_prefix())
            .expect("scan")
            .iter()
            .all(|(key, _)| key != &old_row));
    }

    #[test]
    fn a_stamp_is_checked_by_version_and_not_by_equality() {
        assert!(
            check_schema_stamp(None).expect("no stamp"),
            "an empty store wants stamping",
        );
        assert!(
            !check_schema_stamp(Some(&[STORAGE_SCHEMA_VERSION])).expect("this version"),
            "our own stamp needs no rewrite",
        );
        assert!(
            check_schema_stamp(Some(&[STORAGE_SCHEMA_VERSION - 1])).expect("an older version"),
            "an older store opens and is re-stamped",
        );
        assert!(check_schema_stamp(Some(&[STORAGE_SCHEMA_VERSION + 1])).is_err());
        assert!(check_schema_stamp(Some(&[])).is_err());
    }
}
