// SPDX-License-Identifier: MIT
//! Participant media keys: call v2 (docs/calls.md §Participant media
//! keys).
//!
//! In v1 every member of the conversation's MLS group derives every sender's
//! frame key from the epoch's exporter, in the call or not. v2 makes being IN
//! THE CALL the key boundary and keeps the epoch binding:
//!
//! - **Each participant holds a media secret**: 32 random bytes per device
//!   and call, at a generation that starts at 0. Its frame key is
//!   [`super::call_sender_key_v2`] of the epoch's v2 call root and that
//!   secret, so a member without the secret derives nothing, and a commit
//!   still rekeys everyone.
//! - **Only participants get it.** A joining device makes two fresh HPKE key
//!   pairs for the call, an X-Wing (ML-KEM-768 + X25519) one and an X25519
//!   one, and puts both public keys in its signed `Joined`, with no
//!   media-server session or tracks. A signed `Joined` without both, or
//!   naming a session, binds nothing and is refused. Every other participant seals its
//!   secret, session and tracks to the X-Wing key in a signed `MediaKey`
//!   signal ([`super::MediaGrant`]): HPKE base mode, X-Wing (draft 06),
//!   HKDF-SHA256, AES-128-GCM, `info = "peachy call media key v2" ‖ call_id ‖
//!   u32be(sender_leaf) ‖ u32be(to_leaf)`, so a grant recorded today stays
//!   closed to a quantum computer later, to the other members of the group
//!   too. No grant is sealed to the X25519 key, and none sealed to one
//!   opens. A member that never joins holds no call private key and opens
//!   no grant.
//! - **A newcomer gets the NEXT generation.** A participant that binds a new
//!   participant advances its own secret one step
//!   ([`super::call_media_advance`]), switches to it at once and grants it to
//!   the newcomer alone. The `MediaKey`'s generation tells the participants
//!   already holding the previous one to advance their copy. The newcomer
//!   cannot reverse the step, so it reads nothing sent before it joined.
//! - **A leaver loses it.** On a signed `Left` (opened here), a heartbeat
//!   timeout or an honored `Remove` (the client's call, through
//!   [`Client::call_media_remove`]), every remaining participant draws a
//!   fresh secret, grants it to the remaining participants, and switches to
//!   it [`super::CALL_MEDIA_ROTATE_DELAY_MS`] later so they hold it before
//!   the first frame. The core keeps that due time and switches by itself at
//!   the first door call at or after it (a heartbeat sealed or opened, a
//!   reload of the keys, [`Client::call_media_apply`]): a client cannot
//!   forget the switch, and cannot postpone it. A rotation asked for while
//!   one is pending keeps the pending one's due time, and the next rotation
//!   is drawn when it switches.
//! - **A participant a commit removes is a leaver too.** The commit rekeys
//!   only the v2 call root, which every member derives, the removed device's
//!   own other devices included; its media secrets are what kept it out. So
//!   a commit that takes a bound participant's leaf away owes the same
//!   rotation, paid by [`Client::call_media_on_epoch`] (the client's call on
//!   every epoch change) or by the next [`Client::call_media_remove`].
//! - **Keys come only from a bound leaf.** A grant counts only from a leaf
//!   whose signed `Joined` this device opened, from the same device and the
//!   same participation. A grant that arrives before that `Joined` is held,
//!   a few at most, until it binds.
//! - **A device's participations are ordered.** Its signed `Joined` and
//!   `MediaKey` carry the participation's mark ([`Participation`]: a random
//!   id and a counter the device keeps in its store, raised by one for each
//!   participation, so no wall clock orders them); one without it is
//!   refused. A signed `Joined` from an earlier participation of the device
//!   bound at a leaf than the last one this device bound there (by the MLS
//!   epoch it was sealed in, then the counter) is refused, so a `Joined` the server held back cannot re-bind a
//!   rejoined device to the call key its lost state took with it, nor take
//!   its leaf back to an id it left. A grant counts only under the
//!   participation that sealed it.
//!
//! **No group call runs on a key every member derives.** The core binds no
//! signed `Joined` without both call keys or with a session in it, takes no
//! grant sealed to an X25519 key and seals none, and a `Joined` from a
//! device that is not a participant is refused ([`CALL_STATE_LOST`]).
//!
//! **The state is in memory, per (group, call), and losing it never
//! downgrades the call.** A client rebuilt mid-call (a restart, recovery
//! after a panic, a client reopened on the same store) holds no secret, key
//! pair or bound participant for it. Its core then refuses to seal a
//! `Joined` for the call ([`CALL_STATE_LOST`]), which would go out with no
//! call key. `keys` answers the same. The client joins again: `start`
//! (a fresh secret and key pair, under the participant id it holds), a
//! signed `Joined`, `share`. Every participant takes that `Joined` as a
//! returning device, grants it its secret one step on, and sends its own
//! signed `Joined` again so the rebuilt core can bind it.

use std::collections::{BTreeMap, BTreeSet};

use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto as _;
use openmls_traits::types::{HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType};
use serde_json::{json, Value};

use super::keys::{
    call_key_index_v2, call_media_advance, call_sender_key_v2, CALL_EXPORTER_LABEL_V2,
    CALL_MEDIA_MAX_ADVANCE, CALL_MEDIA_ROTATE_DELAY_MS, CALL_MEDIA_SEED_BYTES, CALL_ROOT_BYTES,
    CALL_SENDER_KEY_BYTES,
};
use super::signal::{
    decode_media_grant_payload, encode_call_signal, encode_media_grant_payload, CallSignal,
    CallSignalBody, MediaGrant, MediaGrantPayload, Participation, CALL_ID_BYTES,
    CALL_MEDIA_PQ_ENC_BYTES, CALL_MEDIA_PQ_PUBLIC_KEY_BYTES, CALL_MEDIA_PUBLIC_KEY_BYTES,
    CALL_PARTICIPATION_BYTES, MAX_CALL_MEDIA_GRANTS,
};
use super::{from_hex, to_hex};
use crate::error::{CredentialRejection, Error, Result};
use crate::group::Client;

/// The HPKE `info` prefix of a media grant; call id, sender leaf and
/// recipient leaf follow.
pub const CALL_MEDIA_KEY_INFO: &[u8] = b"peachy call media key v2";

/// The HPKE suite of a classical media grant: DHKEM(X25519, HKDF-SHA256),
/// HKDF-SHA256, AES-128-GCM: the suite of the X25519 call key a `Joined`
/// names beside its X-Wing one. The core seals no grant under it and takes
/// none from a peer; the fixture's `open_call_media_grant` still opens one,
/// as the fixture pins it, and [`seal_call_media_grant`] refuses an X25519
/// key.
pub const CALL_MEDIA_HPKE: HpkeConfig = HpkeConfig(
    HpkeKemType::DhKem25519,
    HpkeKdfType::HkdfSha256,
    HpkeAeadType::AesGcm128,
);

/// The HPKE suite of a post-quantum media grant: X-Wing (draft 06,
/// ML-KEM-768 + X25519), HKDF-SHA256, AES-128-GCM, the HPKE suite of the
/// group's own ciphersuite. The grant travels inside an MLS application
/// message, which the group's X-Wing KEM already protects from anyone
/// outside the group; this layer keeps it from the group's other members,
/// and keeps it so against a quantum computer too. The suite id is in the
/// HPKE key schedule, so a grant cannot be opened under the other suite.
pub const CALL_MEDIA_HPKE_PQ: HpkeConfig = HpkeConfig(
    HpkeKemType::XWingKemDraft6,
    HpkeKdfType::HkdfSha256,
    HpkeAeadType::AesGcm128,
);

/// The latest participation start a signal carries
/// ([`super::signal::MAX_CALL_CREATED_AT_MS`], 2^53 - 1).
const MAX_STARTED_AT_MS: u64 = 9_007_199_254_740_991;
/// Grants from a leaf whose `Joined` has not bound yet, held per call.
const MAX_HELD_GRANTS: usize = 16;
/// Calls whose media state one client keeps at once.
const MAX_CALLS: usize = 16;
/// What the core says when it holds no participant media state for a call
/// it is asked to seal a `Joined` for, or to answer `keys` for: the client
/// lost it (it was rebuilt), or never asked `start`. A client that believes
/// it is in the call joins again (`start`, a signed `Joined`, `share`).
pub const CALL_STATE_LOST: &str = "call state lost";
/// The grant bytes one `MediaKey` signal carries at most before the next
/// one starts: about seven X-Wing grants, so a sealed signal stays well
/// under a call link log's 16 KiB entry with MLS framing and padding on top.
const GRANT_BYTES_PER_SIGNAL: usize = 10 * 1024;

/// Which participation of a device a `Joined`, `MediaKey` or binding is:
/// its [`Participation`] mark, which every signed `Joined` and `MediaKey`
/// carries (one without it is refused), and its start, which goes out with
/// it and orders nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mark {
    pub(crate) started_at_ms: u64,
    pub(crate) participation: Participation,
}

impl Mark {
    /// The same participation: the same mark.
    fn same(&self, other: &Mark) -> bool {
        self.participation == other.participation
    }

    /// An earlier participation of the same device than `other`: a lower
    /// counter (two marks with one counter, which only a device that lost
    /// its store mints, are neither).
    fn before(&self, other: &Mark) -> bool {
        self.participation.seq < other.participation.seq
    }
}

#[derive(Clone)]
struct Generation {
    generation: u32,
    secret: zeroize::Zeroizing<[u8; CALL_MEDIA_SEED_BYTES]>,
}

struct Own {
    /// The participant id this participation is, as `start` named it (the
    /// server's answer to JoinCall). Only a `Left` naming exactly this id
    /// ends the participation's keys, and a `Joined` names it or is refused.
    participant_id: String,
    /// This participation's mark: its random id and this device's next
    /// participation counter, and when `start` began it (by this device's
    /// clock, later than any participation before it in this core). It goes
    /// out in this participation's every `Joined` and `MediaKey`.
    mark: Mark,
    /// This device's own `Joined` went out for this participation: the core
    /// re-sends it when the call falls back, or a returning device needs it.
    announced: bool,
    /// The participation's X25519 public key: it goes in every signed
    /// `Joined`, where a receiver requires it and tells the participation's
    /// key pair by it. No grant is sealed to it, so its private key is wiped
    /// as soon as it is drawn.
    public_key: [u8; CALL_MEDIA_PUBLIC_KEY_BYTES],
    /// The participation's X-Wing key pair: its public key goes in every
    /// signed `Joined`, and a grant sealed to it opens with the private one.
    pq_public_key: Vec<u8>,
    pq_private_key: zeroize::Zeroizing<Vec<u8>>,
    session_id: String,
    track_names: Vec<String>,
    applied: Generation,
    pending: Option<Generation>,
    /// When `pending` becomes the sending secret, by this client's monotonic
    /// clock (setting the wall clock moves nothing here): set
    /// once, when it is drawn. Nothing moves it later.
    pending_due_ms: u64,
    /// Another rotation was asked for while `pending` was waiting (a second
    /// leaver, who holds `pending` too): drawn when `pending` switches, at
    /// the first door that can hand its grants over.
    rotate_again: bool,
}

impl Own {
    fn latest(&self) -> &Generation {
        self.pending.as_ref().unwrap_or(&self.applied)
    }
}

struct Peer {
    device_id: String,
    participant_id: String,
    /// The participation its binding `Joined` named: only grants sealed
    /// under it count.
    mark: Mark,
    /// Its X25519 call public key: which call key pair its participation
    /// holds. No grant is sealed to it.
    public_key: [u8; CALL_MEDIA_PUBLIC_KEY_BYTES],
    /// Its X-Wing call public key: every grant to it is sealed to this one.
    pq_key: Vec<u8>,
    /// The latest secret this device was granted by this peer.
    granted: Option<Generation>,
    /// The highest generation the peer announced by advancing; at least
    /// `granted`'s.
    announced: u32,
    /// The secret the peer sent under before its last rotation, kept until
    /// `previous_until_ms` (this client's monotonic clock) for the frames it
    /// sends before it applies the new one.
    previous: Option<Generation>,
    previous_until_ms: u64,
    session_id: String,
    track_names: Vec<String>,
}

struct Held {
    sender_leaf: u32,
    device_id: String,
    mark: Mark,
    payload: MediaGrantPayload,
}

/// The last signed `Joined` this device bound at a leaf: whose, sealed at
/// which MLS epoch, from which participation. Kept when the participant
/// leaves or is removed, and dropped when the leaf changes hands.
struct JoinedOrder {
    device_id: String,
    epoch: u64,
    mark: Mark,
}

impl JoinedOrder {
    /// Whether this binding supersedes a signed `Joined` from the same
    /// device, sealed at `epoch` under the participation `mark`: that one
    /// comes from a participation earlier than this one. The device's epoch
    /// only rises, so a later epoch is never earlier; within one epoch the
    /// participation's counter decides ([`Mark::before`]), which no wall
    /// clock moves. The same participation is never earlier (its `Joined`
    /// goes again at every epoch).
    fn supersedes(&self, epoch: u64, mark: &Mark) -> bool {
        !mark.same(&self.mark)
            && (epoch < self.epoch || (epoch == self.epoch && mark.before(&self.mark)))
    }
}

#[derive(Default)]
struct CallMediaState {
    /// A commit took away the leaf of a v2 participant this device granted
    /// its secret to (or another device's signed `Joined` took its place),
    /// and this device has not rotated since: the next
    /// [`Client::call_media_on_epoch`] or [`Client::call_media_remove`] does.
    /// Sticky until paid, whichever door noticed it.
    rotation_owed: bool,
    /// Grants this device owes and sealed nowhere: a seal while a signal
    /// was opened (or an epoch door ran) was refused because this device's
    /// own leaf has lapsed ([`Client::call_media_owe_on_lapse`]). The next
    /// [`Client::call_media_door`] grants the latest secret to every bound
    /// participant; a rotation or `share`, which grant it to all of them,
    /// pay it as well. Sticky until paid.
    grants_unsent: bool,
    /// This device's own `Joined`, re-sent on a fall-back or to a returning
    /// device, was refused the same way; the next door sends it.
    joined_unsent: bool,
    own: Option<Own>,
    peers: BTreeMap<u32, Peer>,
    /// Per leaf, the last signed `Joined` bound there ([`JoinedOrder`]).
    joined_order: BTreeMap<u32, JoinedOrder>,
    /// The start of this device's latest participation in the call, kept
    /// past `end`, so the next one starts later even within a millisecond.
    last_started_at_ms: u64,
    held: Vec<Held>,
    /// Participant ids an admin's `Remove` took out of this call, as this
    /// device honored it: never bound again (R-K10). Coming back is a new
    /// join, under the new random participant id the server gives every
    /// join; a call link's member comes back only through a new admission.
    removed: BTreeSet<String>,
    /// The core switched this device's sending secret at a door that could
    /// not say so; the next door that answers `applied` does.
    applied_unreported: bool,
}

impl CallMediaState {
    /// The participant id of this device's participation, while it is in
    /// the call.
    fn own_participant_id(&self) -> Option<&str> {
        self.own.as_ref().map(|own| own.participant_id.as_str())
    }

    /// Unbind every peer bound under `participant_id`, and drop what their
    /// leaves sent before binding. True when one of them was keyed: it may
    /// hold this device's secret.
    fn unbind_participant_id(&mut self, participant_id: &str) -> bool {
        let leaves: Vec<u32> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.participant_id == participant_id)
            .map(|(leaf, _)| *leaf)
            .collect();
        for leaf in &leaves {
            self.peers.remove(leaf);
        }
        self.held.retain(|held| !leaves.contains(&held.sender_leaf));
        !leaves.is_empty()
    }

    /// Whether `peer` is bound under this device's own participant id. Such
    /// a peer is never listed or granted.
    fn under_own_id(&self, peer: &Peer) -> bool {
        self.own_participant_id() == Some(peer.participant_id.as_str())
    }
}

/// Every call's v2 media state on this client, in memory.
pub(crate) struct CallMediaBook {
    calls: BTreeMap<(Vec<u8>, [u8; CALL_ID_BYTES]), CallMediaState>,
    /// A door that must not fail on what it seals for others is running
    /// ([`Client::call_media_deferring_lapsed_seals`]): a grant or a
    /// re-sent `Joined` refused for this device's lapsed leaf is owed, not
    /// an error.
    defers_lapsed_seals: bool,
}

/// What a seal refused for this device's lapsed leaf leaves owed
/// ([`Client::call_media_owe_on_lapse`]).
#[derive(Clone, Copy)]
enum Owed {
    /// The latest secret, to every bound participant.
    Grants,
    /// This device's own `Joined`.
    Joined,
}

impl CallMediaBook {
    pub(crate) fn new() -> Self {
        Self {
            calls: BTreeMap::new(),
            defers_lapsed_seals: false,
        }
    }

    fn get(&self, group_id: &[u8], call_id: &[u8; CALL_ID_BYTES]) -> Option<&CallMediaState> {
        self.calls.get(&(group_id.to_vec(), *call_id))
    }

    fn get_mut(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
    ) -> Option<&mut CallMediaState> {
        self.calls.get_mut(&(group_id.to_vec(), *call_id))
    }

    fn entry(&mut self, group_id: &[u8], call_id: &[u8; CALL_ID_BYTES]) -> &mut CallMediaState {
        let key = (group_id.to_vec(), *call_id);
        if !self.calls.contains_key(&key) && self.calls.len() >= MAX_CALLS {
            // Forget a call this device is not in before one it is.
            let victim = self
                .calls
                .iter()
                .find(|(_, state)| state.own.is_none())
                .or_else(|| self.calls.iter().next())
                .map(|(key, _)| key.clone());
            if let Some(victim) = victim {
                self.calls.remove(&victim);
            }
        }
        self.calls.entry(key).or_default()
    }

    /// Whether a live `Joined` claiming `leaf` and naming `participant_id`
    /// speaks for another tile: this device's own id, or a participant bound
    /// at another leaf. A participant id is held by one leaf, so its
    /// heartbeat comes from that leaf alone.
    pub(crate) fn live_joined_names_another(
        &self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
        participant_id: &str,
        leaf: u32,
    ) -> bool {
        self.get(group_id, call_id).is_some_and(|state| {
            state.own_participant_id() == Some(participant_id)
                || state
                    .peers
                    .iter()
                    .any(|(at, peer)| *at != leaf && peer.participant_id == participant_id)
        })
    }

    /// Whether this device is a v2 participant in the call.
    pub(crate) fn is_participant(&self, group_id: &[u8], call_id: &[u8; CALL_ID_BYTES]) -> bool {
        self.get(group_id, call_id)
            .is_some_and(|state| state.own.is_some())
    }

    /// Whether sealing this device's own `Left` naming `participant_id` ends
    /// its media keys: only a `Left` naming its CURRENT participation, the
    /// id `start` named, does. A rejoin's `Left` for its old participant
    /// leaves the new one's keys alone in either order relative to `start`,
    /// however many ids came before and whatever this core remembers of
    /// them.
    pub(crate) fn own_left_ends_media(
        &self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
        participant_id: &str,
    ) -> bool {
        self.get(group_id, call_id)
            .and_then(|state| state.own.as_ref())
            .is_some_and(|own| own.participant_id == participant_id)
    }

    /// This device's own `Joined` as it goes out, if it is a v2
    /// participant: its call public keys, never its session or tracks. A
    /// `Joined` naming another id than the one `start` named is refused:
    /// it would carry this participation's key under someone else's tile.
    ///
    /// The id is this device's from `start` on, and a peer bound under it (a
    /// signed `Joined` opened since) would be granted this device's secret
    /// behind its own tile: it is unbound, and a keyed one owes a rotation,
    /// since this device may have granted it its secret already.
    pub(crate) fn outgoing_joined(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
        participant_id: &str,
    ) -> Result<Option<OutgoingJoined>> {
        let Some(state) = self.calls.get_mut(&(group_id.to_vec(), *call_id)) else {
            return Ok(None);
        };
        let Some(own_id) = state.own_participant_id().map(str::to_string) else {
            return Ok(None);
        };
        if own_id != participant_id {
            return Err(Error::invalid(format!(
                "a Joined names {participant_id}, but this device's participation is {own_id}: call_media_start for the new one first"
            )));
        }
        if state.unbind_participant_id(participant_id) {
            state.rotation_owed = true;
        }
        let Some(own) = state.own.as_mut() else {
            return Ok(None);
        };
        own.announced = true;
        Ok(Some(OutgoingJoined {
            public_key: own.public_key,
            pq_public_key: own.pq_public_key.clone(),
            mark: own.mark,
        }))
    }
}

/// What [`CallMediaBook::outgoing_joined`] puts in this device's own
/// `Joined`: its call public keys (the X-Wing one only in a signed
/// `Joined`, which binds; a live one binds nothing and stays small) and
/// its participation's mark.
pub(crate) struct OutgoingJoined {
    pub(crate) public_key: [u8; CALL_MEDIA_PUBLIC_KEY_BYTES],
    pub(crate) pq_public_key: Vec<u8>,
    pub(crate) mark: Mark,
}

/// What a `MediaKey` granted this device, as [`super::OpenedCallSignal::media`]
/// reports it: whose secret, at which generation, and the sender's
/// media-server session and tracks (its pull capability). Never the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedMediaGrant {
    pub sender_leaf: u32,
    pub generation: u32,
    pub session_id: String,
    pub track_names: Vec<String>,
    /// False when the sender's signed `Joined` has not bound yet: the grant
    /// is held, and counts once it does.
    pub bound: bool,
}

/// One sender's v2 frame key at one generation, for the frame encryptor's
/// ring of that sender at `key_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallMediaSenderKey {
    pub leaf_index: u32,
    pub generation: u32,
    pub key_index: u8,
    pub key: crate::secret::Secret<[u8; CALL_SENDER_KEY_BYTES]>,
}

/// A bound participant as this device knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallMediaParticipant {
    pub leaf_index: u32,
    pub participant_id: String,
    /// The media-server session and tracks the participant granted this
    /// device; empty until it has.
    pub session_id: String,
    pub track_names: Vec<String>,
    /// Whether this device holds a key for it.
    pub keyed: bool,
}

/// A v2 call's keys at one epoch: what a participant loads into its frame
/// encryptor, every key at its own `key_index` in its sender's ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallMediaKeys {
    pub epoch: u64,
    pub own_leaf: u32,
    /// The slot this device encrypts its own frames under.
    pub send_key_index: u8,
    /// This device's own keys (the applied generation, and a rotated one not
    /// applied yet), then each keyed participant's: the generation it was
    /// granted or announced, the one before it, and the next advance.
    pub senders: Vec<CallMediaSenderKey>,
    pub participants: Vec<CallMediaParticipant>,
}

impl Client {
    /// This device's next call participation: a fresh random id and the
    /// next value of the counter it keeps in its store
    /// (`storage.rs` `call_participation`), written before it is handed
    /// out, so a participation's counter is never handed out twice by a
    /// device whose store holds, however its wall clock moves.
    pub(crate) fn next_call_participation(&mut self) -> Result<Participation> {
        let id = random_bytes::<{ CALL_PARTICIPATION_BYTES - 8 }>()?;
        let seq = self.synced(|client| {
            let storage = client.peachy_storage();
            let last = storage.call_participation_seq()?;
            let seq = last.saturating_add(1);
            if seq > MAX_STARTED_AT_MS {
                return Err(Error::invalid(
                    "this device has run out of call participations",
                ));
            }
            storage.set_call_participation_seq(seq)?;
            Ok(seq)
        })?;
        Ok(Participation { id, seq })
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out)
        .map_err(|err| Error::invalid(format!("no randomness for a call media key: {err}")))?;
    Ok(out)
}

fn check_call_id(call_id: &[u8]) -> Result<[u8; CALL_ID_BYTES]> {
    call_id.try_into().map_err(|_| {
        Error::invalid(format!(
            "a call id is {CALL_ID_BYTES} bytes, not {}",
            call_id.len()
        ))
    })
}

/// The HPKE `info` of a grant from `sender_leaf` to `to_leaf` in `call_id`.
pub fn call_media_grant_info(call_id: &[u8], sender_leaf: u32, to_leaf: u32) -> Vec<u8> {
    let mut info = Vec::with_capacity(CALL_MEDIA_KEY_INFO.len() + call_id.len() + 8);
    info.extend_from_slice(CALL_MEDIA_KEY_INFO);
    info.extend_from_slice(call_id);
    info.extend_from_slice(&sender_leaf.to_be_bytes());
    info.extend_from_slice(&to_leaf.to_be_bytes());
    info
}

/// A call key pair from 32 bytes of input key material (RFC 9180
/// DeriveKeyPair): `(private, public)`. A client never calls this itself; the
/// fixture pins it.
pub fn call_media_key_pair(ikm: &[u8]) -> Result<(Vec<u8>, [u8; CALL_MEDIA_PUBLIC_KEY_BYTES])> {
    let pair = RustCrypto::default()
        .derive_hpke_keypair(CALL_MEDIA_HPKE, ikm)
        .map_err(|err| Error::invalid(format!("could not make a call key pair: {err:?}")))?;
    let public: [u8; CALL_MEDIA_PUBLIC_KEY_BYTES] = pair
        .public
        .as_slice()
        .try_into()
        .map_err(|_| Error::invalid("a call public key is 32 bytes"))?;
    Ok((pair.private.to_vec(), public))
}

/// A post-quantum call key pair from 32 bytes of input key material:
/// `(private, public)`, the public one an X-Wing key of
/// [`CALL_MEDIA_PQ_PUBLIC_KEY_BYTES`].
pub fn call_media_pq_key_pair(ikm: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let pair = RustCrypto::default()
        .derive_hpke_keypair(CALL_MEDIA_HPKE_PQ, ikm)
        .map_err(|err| Error::invalid(format!("could not make a call key pair: {err:?}")))?;
    if pair.public.len() != CALL_MEDIA_PQ_PUBLIC_KEY_BYTES {
        return Err(Error::invalid(format!(
            "a post-quantum call public key is {CALL_MEDIA_PQ_PUBLIC_KEY_BYTES} bytes"
        )));
    }
    Ok((pair.private.to_vec(), pair.public.clone()))
}

/// Whether `key` is an X-Wing public key a grant can be sealed to: its
/// length, and its ML-KEM-768 encapsulation key (the first 1,184 bytes)
/// passing the modulus check of FIPS 203 §7.2, every 12-bit coefficient of
/// its first 1,152 bytes below q = 3329. A key that fails it makes every
/// seal to it fail, so a `Joined` naming one binds nothing.
pub(crate) fn call_media_pq_key_is_valid(key: &[u8]) -> bool {
    const Q: u16 = 3329;
    const ENCODED_T_BYTES: usize = 3 * 384;
    key.len() == CALL_MEDIA_PQ_PUBLIC_KEY_BYTES
        && key[..ENCODED_T_BYTES].as_chunks::<3>().0.iter().all(|b| {
            let low = u16::from(b[0]) | (u16::from(b[1] & 0x0f) << 8);
            let high = u16::from(b[1] >> 4) | (u16::from(b[2]) << 4);
            low < Q && high < Q
        })
}

/// The HPKE suite a grant whose `enc` is this long was sealed under.
fn suite_for_enc(enc: &[u8]) -> Result<HpkeConfig> {
    match enc.len() {
        CALL_MEDIA_PUBLIC_KEY_BYTES => Ok(CALL_MEDIA_HPKE),
        CALL_MEDIA_PQ_ENC_BYTES => Ok(CALL_MEDIA_HPKE_PQ),
        _ => Err(Error::invalid("the media grant did not open")),
    }
}

/// Seal one grant to a participant's post-quantum call public key
/// ([`CALL_MEDIA_PQ_PUBLIC_KEY_BYTES`]), under [`CALL_MEDIA_HPKE_PQ`]:
/// `(enc, ciphertext)`. Any other key, an X25519 call key among them, is
/// refused: no grant is sealed classically.
pub fn seal_call_media_grant(
    public_key: &[u8],
    call_id: &[u8],
    sender_leaf: u32,
    to_leaf: u32,
    payload: &MediaGrantPayload,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if public_key.len() != CALL_MEDIA_PQ_PUBLIC_KEY_BYTES {
        return Err(Error::invalid(format!(
            "a media grant is sealed only to a {CALL_MEDIA_PQ_PUBLIC_KEY_BYTES}-byte post-quantum call key, not {} bytes",
            public_key.len()
        )));
    }
    let suite = CALL_MEDIA_HPKE_PQ;
    // The grant's plaintext carries the media seed: wiped when dropped.
    let plaintext = zeroize::Zeroizing::new(encode_media_grant_payload(payload)?);
    let sealed = RustCrypto::default()
        .hpke_seal(
            suite,
            public_key,
            &call_media_grant_info(call_id, sender_leaf, to_leaf),
            &[],
            &plaintext[..],
        )
        .map_err(|err| Error::invalid(format!("could not seal a media grant: {err:?}")))?;
    Ok((
        sealed.kem_output.as_slice().to_vec(),
        sealed.ciphertext.as_slice().to_vec(),
    ))
}

/// Open one grant with this participant's call private key: the X-Wing one
/// for a grant whose `enc` is [`CALL_MEDIA_PQ_ENC_BYTES`], the X25519 one for
/// a 32-byte `enc`. Refuses a grant sealed to another key, for another call,
/// from or to another leaf, or changed in any bit.
///
/// The fixture's door alone: no grant is sealed classically, and a client
/// opens only X-Wing grants, through its own door.
#[cfg(any(test, feature = "fixture"))]
pub fn open_call_media_grant(
    private_key: &[u8],
    call_id: &[u8],
    sender_leaf: u32,
    to_leaf: u32,
    enc: &[u8],
    ciphertext: &[u8],
) -> Result<MediaGrantPayload> {
    open_call_media_grant_any(private_key, call_id, sender_leaf, to_leaf, enc, ciphertext)
}

fn open_call_media_grant_any(
    private_key: &[u8],
    call_id: &[u8],
    sender_leaf: u32,
    to_leaf: u32,
    enc: &[u8],
    ciphertext: &[u8],
) -> Result<MediaGrantPayload> {
    let input = HpkeCiphertext {
        kem_output: enc.to_vec().into(),
        ciphertext: ciphertext.to_vec().into(),
    };
    let suite = suite_for_enc(enc)?;
    let plaintext = zeroize::Zeroizing::new(
        RustCrypto::default()
            .hpke_open(
                suite,
                &input,
                private_key,
                &call_media_grant_info(call_id, sender_leaf, to_leaf),
                &[],
            )
            .map_err(|_| Error::invalid("the media grant did not open"))?,
    );
    decode_media_grant_payload(&plaintext)
}

impl Client {
    fn call_media_group_epoch_root(
        &self,
        group_id: &[u8],
        call_id: &[u8],
        pending: bool,
    ) -> Result<(u64, zeroize::Zeroizing<[u8; CALL_ROOT_BYTES]>)> {
        let (epoch, root) = if pending {
            (
                self.epoch(group_id)?.saturating_add(1),
                self.export_pending_secret(
                    group_id,
                    CALL_EXPORTER_LABEL_V2,
                    call_id,
                    CALL_ROOT_BYTES,
                )?,
            )
        } else {
            (
                self.epoch(group_id)?,
                self.export_secret(group_id, CALL_EXPORTER_LABEL_V2, call_id, CALL_ROOT_BYTES)?,
            )
        };
        let root = zeroize::Zeroizing::new(root);
        // The caller's copy wipes itself too.
        let root: [u8; CALL_ROOT_BYTES] = root
            .as_slice()
            .try_into()
            .map_err(|_| Error::invalid("the exporter returned the wrong length"))?;
        Ok((epoch, zeroize::Zeroizing::new(root)))
    }

    /// Forget every peer whose leaf no longer holds the device that bound it
    /// (a commit removed it, or another device took the leaf). The epoch
    /// change that did it rekeyed only the call root, which any member
    /// derives, the removed device's other devices included; so when this
    /// device is in the call and had granted its secret to a peer it drops,
    /// a rotation is owed, exactly as for a leaver. Every door that touches
    /// a call's media state runs this first, every signal door included, so
    /// no order of opens and epoch hooks loses the debt. A peer bound under
    /// this device's own participant id is stale too, however it got there.
    pub(crate) fn call_media_prune(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
    ) -> Result<()> {
        let roster: BTreeMap<u32, String> = self
            .roster(group_id)?
            .into_iter()
            .filter_map(|entry| {
                entry
                    .identity
                    .ok()
                    .map(|identity| (entry.leaf_index, identity.device_id))
            })
            .collect();
        if let Some(state) = self.call_media.get_mut(group_id, call_id) {
            let mut dropped_keyed = false;
            state.peers.retain(|leaf, peer| {
                let stays = roster.get(leaf) == Some(&peer.device_id);
                if !stays {
                    dropped_keyed = true;
                }
                stays
            });
            state
                .joined_order
                .retain(|leaf, order| roster.get(leaf) == Some(&order.device_id));
            if let Some(own_id) = state.own_participant_id().map(str::to_string) {
                dropped_keyed |= state.unbind_participant_id(&own_id);
            }
            if dropped_keyed && state.own.is_some() {
                state.rotation_owed = true;
            }
        }
        Ok(())
    }

    /// Draw a fresh random secret at the next generation as this device's
    /// pending one, due [`CALL_MEDIA_ROTATE_DELAY_MS`] from now, and grant it
    /// to every bound v2 participant (`rotated = true`). Pays any rotation
    /// owed. `None` when this device is not in the call.
    ///
    /// While a rotation is pending this draws and grants nothing (`Some` of
    /// no envelopes): whoever this one is for holds the pending secret too,
    /// so the next rotation is drawn when the pending one switches
    /// ([`Client::call_media_promote_due`]), and the pending one keeps its
    /// due time. A later leaver never postpones the switch that cuts off an
    /// earlier one.
    fn call_media_rotate(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
    ) -> Result<Option<Vec<Vec<u8>>>> {
        let now_ms = self.now_monotonic_ms();
        let Some(state) = self.call_media.get_mut(group_id, call_id) else {
            return Ok(None);
        };
        state.rotation_owed = false;
        let Some(own) = state.own.as_mut() else {
            return Ok(None);
        };
        if own.pending.is_some() {
            own.rotate_again = true;
            return Ok(Some(Vec::new()));
        }
        let generation = own
            .latest()
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::invalid("this call has run out of media generations"))?;
        own.pending = Some(Generation {
            generation,
            secret: zeroize::Zeroizing::new(random_bytes::<CALL_MEDIA_SEED_BYTES>()?),
        });
        own.pending_due_ms = now_ms.saturating_add(CALL_MEDIA_ROTATE_DELAY_MS);
        own.rotate_again = false;
        // Granted to everyone: any grant still owed is paid with it (or
        // owed again, should this seal be refused too).
        state.grants_unsent = false;
        let recipients = self.call_media_recipients(group_id, call_id);
        self.call_media_seal_grants(group_id, call_id, true, &recipients)
            .map(Some)
    }

    /// Switch this device's sending secret to the pending one once its due
    /// time has come. Every door that touches a call's media state runs this
    /// first, every signal sealed or opened included (a door that removes
    /// participants runs it once they are out, so a rotation it chains is
    /// never granted to them), so the switch happens
    /// at the first door call at or after the due time whether or not the
    /// client keeps a timer: a live call's own heartbeat goes out every 10 s.
    ///
    /// With `hand_over` (a door that answers `send`), it then draws the
    /// rotation asked for while the switched one was pending, and returns its
    /// grants. A door that cannot hand envelopes over (a seal, the Rust
    /// `keys`) leaves that rotation to the next door that can, so it is drawn
    /// only when its grants go out, and its due time counts from then.
    pub(crate) fn call_media_promote_due(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
        hand_over: bool,
    ) -> Result<Vec<Vec<u8>>> {
        let now_ms = self.now_monotonic_ms();
        let Some(state) = self.call_media.get_mut(group_id, call_id) else {
            return Ok(Vec::new());
        };
        let Some(own) = state.own.as_mut() else {
            return Ok(Vec::new());
        };
        if now_ms >= own.pending_due_ms {
            if let Some(pending) = own.pending.take() {
                own.applied = pending;
                state.applied_unreported = true;
            }
        }
        let chained = own.pending.is_none() && own.rotate_again;
        if !(chained && hand_over) {
            return Ok(Vec::new());
        }
        Ok(self
            .call_media_rotate(group_id, call_id)?
            .unwrap_or_default())
    }

    /// The roster read, then the due switch and any chained rotation: what
    /// every door that touches a call's media state and answers `send` runs
    /// first, but the two that remove participants, which take them out
    /// between the two steps. Returns the chained rotation's grants, to send
    /// first.
    pub(crate) fn call_media_door(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
    ) -> Result<Vec<Vec<u8>>> {
        self.call_media_prune(group_id, call_id)?;
        let mut send = self.call_media_promote_due(group_id, call_id, true)?;
        send.extend(self.call_media_pay_unsent(group_id, call_id)?);
        Ok(send)
    }

    /// Run `door` so that a grant or re-sent `Joined` it seals for others,
    /// refused because this device's own leaf has lapsed, is owed rather
    /// than failing it: what opens a peer's signal, mid-drain, must still
    /// hand the signal back, and the renewal the app runs next cannot run
    /// inside it. The owed envelopes go at the next door after the renewal
    /// ([`Self::call_media_door`]: the renewal's own epoch, the next signal
    /// opened, the next apply).
    pub(crate) fn call_media_deferring_lapsed_seals<T>(
        &mut self,
        door: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let was = std::mem::replace(&mut self.call_media.defers_lapsed_seals, true);
        let out = door(self);
        self.call_media.defers_lapsed_seals = was;
        out
    }

    /// `sealed`, unless it was refused because this device's own leaf has
    /// lapsed while [`Self::call_media_deferring_lapsed_seals`] runs: then
    /// nothing, and what it was ([`Owed`]) is owed.
    fn call_media_owe_on_lapse(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
        sealed: Result<Vec<Vec<u8>>>,
        owed: Owed,
    ) -> Result<Vec<Vec<u8>>> {
        match sealed {
            Err(Error::CredentialRejected(CredentialRejection::Expired))
                if self.call_media.defers_lapsed_seals =>
            {
                let state = self.call_media.entry(group_id, call_id);
                match owed {
                    Owed::Grants => state.grants_unsent = true,
                    Owed::Joined => state.joined_unsent = true,
                }
                Ok(Vec::new())
            }
            other => other,
        }
    }

    /// What [`Self::call_media_owe_on_lapse`] left owed, sent now: this
    /// device's own `Joined`, then its latest secret granted to every bound
    /// participant. Never fails on a seal still refused for the lapsed
    /// leaf; that stays owed. Nothing once this device left the call.
    fn call_media_pay_unsent(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
    ) -> Result<Vec<Vec<u8>>> {
        let Some(state) = self.call_media.get_mut(group_id, call_id) else {
            return Ok(Vec::new());
        };
        let joined = std::mem::take(&mut state.joined_unsent);
        let grants = std::mem::take(&mut state.grants_unsent);
        if !(joined || grants) || state.own.is_none() {
            return Ok(Vec::new());
        }
        self.call_media_deferring_lapsed_seals(|client| {
            let mut send = Vec::new();
            if joined {
                if let Some(signal) = client.call_media_own_joined(group_id, call_id)? {
                    let sealed = client
                        .seal_call_signal_on_mls_lane_now(group_id, &signal)
                        .map(|envelope| vec![envelope]);
                    send.extend(client.call_media_owe_on_lapse(
                        group_id,
                        call_id,
                        sealed,
                        Owed::Joined,
                    )?);
                }
            }
            if grants {
                let recipients = client.call_media_recipients(group_id, call_id);
                send.extend(client.call_media_seal_grants(group_id, call_id, true, &recipients)?);
            }
            Ok(send)
        })
    }

    /// This device's own signed `Joined` for the call, as it went out, once
    /// it went out (`None` before, or out of the call).
    fn call_media_own_joined(
        &self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
    ) -> Result<Option<CallSignal>> {
        let own_leaf = self.own_leaf(group_id)?;
        Ok(self
            .call_media
            .get(group_id, call_id)
            .and_then(|state| state.own.as_ref())
            .filter(|own| own.announced)
            .map(|own| {
                CallSignal::new(
                    *call_id,
                    CallSignalBody::Joined {
                        participant_id: own.participant_id.clone(),
                        session_id: String::new(),
                        track_names: Vec::new(),
                        leaf_index: own_leaf,
                        media_key: own.public_key.to_vec(),
                        started_at_ms: own.mark.started_at_ms,
                        media_key_pq: own.pq_public_key.clone(),
                        participation: Some(own.mark.participation),
                    },
                )
            }))
    }

    /// Whether the core switched this device's sending secret since a door
    /// last said so, taken. A client reloads the keys when it did.
    pub(crate) fn call_media_take_applied(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
    ) -> bool {
        self.call_media
            .get_mut(group_id, call_id)
            .is_some_and(|state| std::mem::take(&mut state.applied_unreported))
    }

    /// How long until the pending rotation switches, while one is pending:
    /// the same due time at every door, however many rotations were asked
    /// for since it was drawn (0 once it is due and no door has run since).
    /// `None` when nothing is pending.
    pub fn call_media_apply_after_ms(&self, group_id: &[u8], call_id: &[u8]) -> Option<u64> {
        let call_id: [u8; CALL_ID_BYTES] = call_id.try_into().ok()?;
        let own = self.call_media.get(group_id, &call_id)?.own.as_ref()?;
        own.pending.as_ref()?;
        Some(own.pending_due_ms.saturating_sub(self.now_monotonic_ms()))
    }

    /// Seal `MediaKey` signals granting `generation` to `recipients`, as many
    /// signals as the grants need. Every one goes signed on the MLS lane.
    /// Refused for this device's lapsed leaf inside
    /// [`Self::call_media_deferring_lapsed_seals`], the grants are owed
    /// ([`Self::call_media_owe_on_lapse`]).
    fn call_media_seal_grants(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
        rotated: bool,
        recipients: &[(u32, Vec<u8>)],
    ) -> Result<Vec<Vec<u8>>> {
        let sealed = self.call_media_seal_grants_now(group_id, call_id, rotated, recipients);
        self.call_media_owe_on_lapse(group_id, call_id, sealed, Owed::Grants)
    }

    fn call_media_seal_grants_now(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
        rotated: bool,
        recipients: &[(u32, Vec<u8>)],
    ) -> Result<Vec<Vec<u8>>> {
        let own_leaf = self.own_leaf(group_id)?;
        let (payload, mark) = {
            let own = self
                .call_media
                .get(group_id, call_id)
                .and_then(|state| state.own.as_ref())
                .ok_or_else(|| Error::invalid("this device is not in that call"))?;
            let latest = own.latest();
            (
                MediaGrantPayload {
                    generation: latest.generation,
                    secret: crate::secret::Secret::new(*latest.secret),
                    session_id: own.session_id.clone(),
                    track_names: own.track_names.clone(),
                },
                own.mark,
            )
        };
        // Sealed to each recipient on its own: a key no grant can be sealed
        // to (bound keys are checked, so none should be) costs that
        // recipient its grant and nobody else theirs.
        let mut grants = Vec::with_capacity(recipients.len());
        for (to_leaf, pq_key) in recipients {
            let (enc, ciphertext) =
                match seal_call_media_grant(pq_key, call_id, own_leaf, *to_leaf, &payload) {
                    Ok(sealed) => sealed,
                    Err(err) => {
                        log::warn!("mls: no media grant for leaf {to_leaf}: {err}");
                        continue;
                    }
                };
            grants.push(MediaGrant {
                to_leaf: *to_leaf,
                enc,
                ciphertext,
            });
        }
        // Several signals when one would pass the grant count or the signal
        // size; an advance always has exactly one grant.
        let mut envelopes = Vec::new();
        let mut batch: Vec<MediaGrant> = Vec::new();
        let mut batch_bytes = 0usize;
        let flush = |client: &mut Client, batch: &mut Vec<MediaGrant>| -> Result<Option<Vec<u8>>> {
            if batch.is_empty() {
                return Ok(None);
            }
            let signal = CallSignal::new(
                *call_id,
                CallSignalBody::MediaKey {
                    generation: payload.generation,
                    rotated,
                    grants: std::mem::take(batch),
                    started_at_ms: mark.started_at_ms,
                    participation: Some(mark.participation),
                },
            );
            client
                .seal_call_signal_on_mls_lane_now(group_id, &signal)
                .map(Some)
        };
        for grant in grants {
            let size = grant.enc.len() + grant.ciphertext.len() + 16;
            if !batch.is_empty()
                && (batch.len() >= MAX_CALL_MEDIA_GRANTS
                    || batch_bytes + size > GRANT_BYTES_PER_SIGNAL)
            {
                envelopes.extend(flush(self, &mut batch)?);
                batch_bytes = 0;
            }
            batch_bytes += size;
            batch.push(grant);
        }
        envelopes.extend(flush(self, &mut batch)?);
        Ok(envelopes)
    }

    /// Put `key` in place of the X-Wing call key this device bound for the
    /// peer at `leaf`, as written. A test door and nothing else, behind
    /// `fixture` and exported through no binding: a bound key is checked, so
    /// only this reaches a key no grant can be sealed to, which a test needs
    /// to show that such a key costs that peer its grant and nobody else
    /// theirs. Returns whether a peer was bound there.
    #[cfg(feature = "fixture")]
    #[doc(hidden)]
    pub fn call_media_replace_peer_key_as_written(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
        leaf: u32,
        key: Vec<u8>,
    ) -> bool {
        match self
            .call_media
            .get_mut(group_id, call_id)
            .and_then(|state| state.peers.get_mut(&leaf))
        {
            Some(peer) => {
                peer.pq_key = key;
                true
            }
            None => false,
        }
    }

    /// The bound participants other than this device, as grant recipients:
    /// each one's leaf and X-Wing call key. Never a peer under this device's
    /// own participant id.
    fn call_media_recipients(
        &self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
    ) -> Vec<(u32, Vec<u8>)> {
        let own_leaf = self.own_leaf(group_id).ok();
        self.call_media
            .get(group_id, call_id)
            .map(|state| {
                state
                    .peers
                    .iter()
                    .filter(|(leaf, _)| Some(**leaf) != own_leaf)
                    .filter(|(_, peer)| !state.under_own_id(peer))
                    .map(|(leaf, peer)| (*leaf, peer.pq_key.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Join a call as a v2 participant `participant_id` (the server's answer
    /// to JoinCall): a fresh media secret at generation 0 and fresh call key
    /// pairs (X25519 and X-Wing), and the media-server session and tracks
    /// this device publishes, which travel only in grants. Returns the X25519
    /// call public key; the core puts both in the signed `Joined`.
    /// Then send a signed `Joined` under that id
    /// ([`Client::seal_call_signal_on_mls_lane`] fills in the key and leaves
    /// the session and tracks out), and then [`Client::call_media_share`].
    ///
    /// Joining again replaces both secrets and the id: only a `Left` naming
    /// the new id ends the new participation, so the old participant's
    /// `Left` (sent before or after this) ends nothing new. A client whose
    /// core lost the call's state ([`CALL_STATE_LOST`]) asks this again under
    /// the id it holds. An id this device's `remove` took out of the call
    /// is refused. A `start` that fails changes nothing and licenses
    /// nothing: the client treats it as a failed join.
    pub fn call_media_start(
        &mut self,
        group_id: &[u8],
        call_id: &[u8],
        participant_id: &str,
        session_id: &str,
        track_names: &[String],
    ) -> Result<[u8; CALL_MEDIA_PUBLIC_KEY_BYTES]> {
        let call_id = check_call_id(call_id)?;
        self.own_leaf(group_id)?;
        if participant_id.is_empty() {
            return Err(Error::invalid(
                "`start` needs the participant id it joins as",
            ));
        }
        // The signal codec's bounds on the id, checked now rather than at the
        // first `Joined` or `Left`.
        encode_call_signal(&CallSignal::new(
            call_id,
            CallSignalBody::Left {
                participant_id: participant_id.to_string(),
            },
        ))?;
        // The payload codec's bounds, checked now rather than at the first grant.
        encode_media_grant_payload(&MediaGrantPayload {
            generation: 0,
            secret: crate::secret::Secret::new([0u8; CALL_MEDIA_SEED_BYTES]),
            session_id: session_id.to_string(),
            track_names: track_names.to_vec(),
        })?;
        // An id an admin's Remove took out is never bound again, this
        // device's own included: a rejoin asks JoinCall for a fresh one.
        if self
            .call_media
            .get(group_id, &call_id)
            .is_some_and(|state| state.removed.contains(participant_id))
        {
            return Err(Error::invalid(format!(
                "`start` names {participant_id}, which was removed from this call"
            )));
        }
        let public_key = {
            let (private_key, public_key) = call_media_key_pair(&random_bytes::<32>()?)?;
            drop(zeroize::Zeroizing::new(private_key));
            public_key
        };
        let (pq_private_key, pq_public_key) = call_media_pq_key_pair(&random_bytes::<32>()?)?;
        let secret = random_bytes::<CALL_MEDIA_SEED_BYTES>()?;
        let participation = self.next_call_participation()?;
        let now_ms = self.now_unix_ms();
        let state = self.call_media.entry(group_id, &call_id);
        // Later than this core's previous participation in the call, even
        // within one millisecond; a rebuilt core starts from its clock. The
        // mark, not the start, orders participations.
        let started_at_ms = now_ms
            .max(state.last_started_at_ms.saturating_add(1))
            .min(MAX_STARTED_AT_MS);
        state.last_started_at_ms = started_at_ms;
        // The id is this device's from now on: a peer bound under it is stale.
        state.unbind_participant_id(participant_id);
        state.own = Some(Own {
            participant_id: participant_id.to_string(),
            mark: Mark {
                started_at_ms,
                participation,
            },
            announced: false,
            public_key,
            pq_public_key,
            pq_private_key: zeroize::Zeroizing::new(pq_private_key),
            session_id: session_id.to_string(),
            track_names: track_names.to_vec(),
            applied: Generation {
                generation: 0,
                secret: zeroize::Zeroizing::new(secret),
            },
            pending: None,
            pending_due_ms: 0,
            rotate_again: false,
        });
        // A fresh secret: nobody holds it, so nothing is owed.
        state.rotation_owed = false;
        state.held.clear();
        state.applied_unreported = false;
        Ok(public_key)
    }

    /// Grant this device's current secret to every bound v2 participant:
    /// right after its own signed `Joined`. Returns the envelopes to send
    /// (`SendSealed`, not urgent).
    ///
    /// A rotation still owed is paid here, and at once: the secret switches
    /// to a fresh random one before it is shared, so a peer unbound since it
    /// was granted the old one (one bound under the id this device's own
    /// `Joined` then took) reads nothing this device sends from now on.
    pub fn call_media_share(&mut self, group_id: &[u8], call_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        let call_id = check_call_id(call_id)?;
        self.call_media_prune(group_id, &call_id)?;
        // The fresh secret below pays a chained rotation too, so none is
        // drawn here.
        self.call_media_promote_due(group_id, &call_id, false)?;
        if let Some(state) = self.call_media.get_mut(group_id, &call_id) {
            let chained = state
                .own
                .as_ref()
                .is_some_and(|own| own.pending.is_none() && own.rotate_again);
            if state.rotation_owed || chained {
                if let Some(own) = state.own.as_mut() {
                    let generation = own.latest().generation.checked_add(1).ok_or_else(|| {
                        Error::invalid("this call has run out of media generations")
                    })?;
                    own.applied = Generation {
                        generation,
                        secret: zeroize::Zeroizing::new(random_bytes::<CALL_MEDIA_SEED_BYTES>()?),
                    };
                    // Fresh, and nobody holds it: nothing pending or chained
                    // is left to rotate past.
                    own.pending = None;
                    own.rotate_again = false;
                    state.rotation_owed = false;
                }
            }
        }
        // Granted to everyone: any grant still owed is paid with it.
        if let Some(state) = self.call_media.get_mut(group_id, &call_id) {
            state.grants_unsent = false;
        }
        let recipients = self.call_media_recipients(group_id, &call_id);
        self.call_media_seal_grants(group_id, &call_id, true, &recipients)
    }

    /// A bound participant is gone: its signed `Left` (which
    /// [`Client::open_call_signal`] handles itself), its heartbeat went stale,
    /// or this device honored a `Remove` of it. Forgets its key and, if this
    /// device is in the call, draws a fresh secret, grants it to the
    /// participants that remain, and returns the envelopes. The core
    /// switches to it [`CALL_MEDIA_ROTATE_DELAY_MS`] later by itself
    /// ([`Client::call_media_promote_due`]); while a rotation is pending,
    /// this one is chained after it instead. A leaf a commit already took
    /// away rotates here too while the rotation it owes is unpaid.
    pub fn call_media_remove(
        &mut self,
        group_id: &[u8],
        call_id: &[u8],
        leaf_index: u32,
    ) -> Result<Vec<Vec<u8>>> {
        let call_id = check_call_id(call_id)?;
        self.call_media_prune(group_id, &call_id)?;
        let removed = match self.call_media.get_mut(group_id, &call_id) {
            Some(state) => {
                let removed = state.peers.remove(&leaf_index).is_some();
                if removed || state.rotation_owed {
                    state.held.retain(|held| held.sender_leaf != leaf_index);
                }
                removed
            }
            None => false,
        };
        self.call_media_after_removal(group_id, &call_id, removed)
    }

    /// The rest of a door that takes participants out, run once they are
    /// out: the due switch and any chained rotation, which therefore grants
    /// nothing to a participant this door removed, then the rotation the
    /// removal owes, unless that chained draw already left them out.
    fn call_media_after_removal(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
        removed: bool,
    ) -> Result<Vec<Vec<u8>>> {
        let pending_before = self.call_media_pending_generation(group_id, call_id);
        let mut send = self.call_media_promote_due(group_id, call_id, true)?;
        let pending_after = self.call_media_pending_generation(group_id, call_id);
        let drew = pending_after.is_some() && pending_after != pending_before;
        let owed = self
            .call_media
            .get(group_id, call_id)
            .is_some_and(|state| state.rotation_owed);
        if drew || !(removed || owed) {
            return Ok(send);
        }
        send.extend(
            self.call_media_rotate(group_id, call_id)?
                .unwrap_or_default(),
        );
        Ok(send)
    }

    /// The generation of this device's pending secret in the call, while one
    /// is pending.
    fn call_media_pending_generation(
        &self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
    ) -> Option<u32> {
        self.call_media
            .get(group_id, call_id)?
            .own
            .as_ref()?
            .pending
            .as_ref()
            .map(|pending| pending.generation)
    }

    /// This device honored an admin's `Remove` of `participant_id`: the id is
    /// never bound again in this call ([`Client::open_call_signal`] refuses a
    /// signed `Joined` under it), and every leaf bound under it goes as
    /// [`Client::call_media_remove`] takes a leaf: its key is forgotten and,
    /// if this device is in the call, its secret rotates past them, once. A
    /// leaf the same device holds under another id (its own rejoin) stays.
    /// So the participants [`Client::call_media_keys`] lists, the ones this
    /// device grants to, and the tiles a client shows stay one set. Naming
    /// this device's own id ends its participation, as
    /// [`Client::call_media_end`] does, and `start` under that id is refused
    /// from then on.
    pub fn call_media_remove_participant(
        &mut self,
        group_id: &[u8],
        call_id: &[u8],
        participant_id: &str,
    ) -> Result<Vec<Vec<u8>>> {
        let checked = check_call_id(call_id)?;
        if participant_id.is_empty() {
            return Err(Error::invalid("a removed participant has an id"));
        }
        self.call_media_prune(group_id, &checked)?;
        let state = self.call_media.entry(group_id, &checked);
        state.removed.insert(participant_id.to_string());
        // No peer is ever bound under this device's own id, so ending its
        // participation is all a Remove of it owes.
        if state.own_participant_id() == Some(participant_id) {
            self.call_media_forget_own(group_id, &checked);
            return Ok(Vec::new());
        }
        let leaves: Vec<u32> = state
            .peers
            .iter()
            .filter(|(_, peer)| peer.participant_id == participant_id)
            .map(|(leaf, _)| *leaf)
            .collect();
        for leaf in &leaves {
            state.peers.remove(leaf);
        }
        state
            .held
            .retain(|held| !leaves.contains(&held.sender_leaf));
        self.call_media_after_removal(group_id, &checked, !leaves.is_empty())
    }

    /// The group's epoch changed while this call is on: a client calls this
    /// on every epoch change it sees, before or after reloading
    /// [`Client::call_media_keys`]. A commit that took away the leaf of a
    /// participant this device granted its secret to is a leave: this device
    /// draws a fresh secret, grants it to the participants that remain and
    /// returns the envelopes (`Some`); the core switches to it
    /// [`CALL_MEDIA_ROTATE_DELAY_MS`] later by itself or, while a rotation
    /// is pending, chains this one after it. `None` when nothing rotated and
    /// nothing was owed from before (nobody left, or this device is not in
    /// the call); [`Client::call_media_apply_after_ms`] says whether a
    /// rotation is pending, whichever door drew it. Calling it again for the
    /// same epoch rotates nothing more. The
    /// removal may have been noticed already by a signal opened since the
    /// commit (every signal door reads the roster); the rotation it owes stays
    /// owed until this, or a `remove`, pays it, so this may run after the
    /// whole mailbox page that carried the commit.
    ///
    /// Run mid-drain, after a commit: a grant refused for this device's own
    /// lapsed leaf is owed rather than failing it
    /// ([`Self::call_media_deferring_lapsed_seals`]).
    pub fn call_media_on_epoch(
        &mut self,
        group_id: &[u8],
        call_id: &[u8],
    ) -> Result<Option<Vec<Vec<u8>>>> {
        let call_id = check_call_id(call_id)?;
        self.call_media_deferring_lapsed_seals(|client| {
            let mut send = client.call_media_door(group_id, &call_id)?;
            let owed = client
                .call_media
                .get(group_id, &call_id)
                .is_some_and(|state| state.rotation_owed && state.own.is_some());
            if owed {
                send.extend(
                    client
                        .call_media_rotate(group_id, &call_id)?
                        .unwrap_or_default(),
                );
            } else if send.is_empty() {
                return Ok(None);
            }
            Ok(Some(send))
        })
    }

    /// Switch this device's sending key to the secret its last rotation
    /// drew, if that rotation is due ([`CALL_MEDIA_ROTATE_DELAY_MS`] after it
    /// was drawn, by this client's monotonic clock). Before then, or with nothing
    /// pending, it changes nothing. The core switches by itself at any door
    /// at or after the due time, so this is only the door a client's timer
    /// knocks at. Returns the envelopes owed: the next rotation, when another
    /// was asked for while this one was pending.
    pub fn call_media_apply(&mut self, group_id: &[u8], call_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        let call_id = check_call_id(call_id)?;
        self.call_media_door(group_id, &call_id)
    }

    /// This device left the call: forget its secrets, its call key pair and
    /// every key and session it was granted. Who is in the call (each bound
    /// participant's device and call public key) stays, so a rejoin can grant
    /// to them again; a signed `Left` still removes a participant. A `Joined`
    /// is refused after it until `start`: `end` never licenses a keyless
    /// one.
    pub fn call_media_end(&mut self, group_id: &[u8], call_id: &[u8]) -> Result<()> {
        let call_id = check_call_id(call_id)?;
        self.call_media_forget_own(group_id, &call_id);
        Ok(())
    }

    /// What sealing this device's own `Left` for its current participation
    /// does: [`Client::call_media_end`].
    pub(crate) fn call_media_end_by_own_left(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
    ) {
        self.call_media_forget_own(group_id, call_id);
    }

    fn call_media_forget_own(&mut self, group_id: &[u8], call_id: &[u8; CALL_ID_BYTES]) {
        if let Some(state) = self.call_media.get_mut(group_id, call_id) {
            state.own = None;
            state.rotation_owed = false;
            state.held.clear();
            state.applied_unreported = false;
            for peer in state.peers.values_mut() {
                peer.granted = None;
                peer.announced = 0;
                peer.previous = None;
                peer.previous_until_ms = 0;
                peer.session_id.clear();
                peer.track_names.clear();
            }
        }
    }

    /// The call's v2 keys at the group's current epoch, or (with `pending`) at
    /// the epoch this device's staged commit makes. Called again on every
    /// epoch change, grant, announced advance, rotation and apply; the client
    /// keeps the previous epoch's keys for [`super::CALL_KEY_GRACE_MS`].
    pub fn call_media_keys(
        &mut self,
        group_id: &[u8],
        call_id: &[u8],
        pending: bool,
    ) -> Result<CallMediaKeys> {
        let call_id = check_call_id(call_id)?;
        self.call_media_prune(group_id, &call_id)?;
        // A due rotation switches here too; a chained one waits for a door
        // that can hand its grants over.
        self.call_media_promote_due(group_id, &call_id, false)?;
        let (epoch, root) = self.call_media_group_epoch_root(group_id, &call_id, pending)?;
        let own_leaf = self.own_leaf(group_id)?;
        let now_ms = self.now_monotonic_ms();
        let not_in = || {
            Error::invalid(format!(
                "{CALL_STATE_LOST}: this device is not in that call (`start` to join it again)"
            ))
        };
        let state = self
            .call_media
            .get(group_id, &call_id)
            .filter(|state| state.own.is_some())
            .ok_or_else(not_in)?;
        let own = state.own.as_ref().ok_or_else(not_in)?;
        let key_of = |leaf: u32, generation: &Generation| -> Result<CallMediaSenderKey> {
            Ok(CallMediaSenderKey {
                leaf_index: leaf,
                generation: generation.generation,
                key_index: call_key_index_v2(epoch, generation.generation),
                key: call_sender_key_v2(&root[..], &generation.secret[..], leaf)?.into(),
            })
        };
        let mut participants = Vec::with_capacity(state.peers.len());
        // Grown by wiping: a reallocation would leave the keys behind.
        let mut senders = Vec::new();
        push_wiping(&mut senders, key_of(own_leaf, &own.applied)?);
        if let Some(rotated) = &own.pending {
            push_wiping(&mut senders, key_of(own_leaf, rotated)?);
        }
        for (leaf, peer) in &state.peers {
            // Never this device, nor a peer under its own participant id.
            if *leaf == own_leaf || state.under_own_id(peer) {
                continue;
            }
            if let Some(previous) = &peer.previous {
                if now_ms < peer.previous_until_ms {
                    push_wiping(&mut senders, key_of(*leaf, previous)?);
                }
            }
            if let Some(granted) = &peer.granted {
                // From the generation before the announced one (frames in
                // flight across an advance) to the next advance (a newcomer
                // this device has not heard of yet).
                let first = peer.announced.saturating_sub(1).max(granted.generation);
                let mut current = granted.clone();
                while current.generation < first {
                    current = Generation {
                        generation: current.generation + 1,
                        secret: zeroize::Zeroizing::new(call_media_advance(&current.secret[..])?),
                    };
                }
                let last = peer.announced.saturating_add(1);
                loop {
                    push_wiping(&mut senders, key_of(*leaf, &current)?);
                    if current.generation >= last {
                        break;
                    }
                    current = Generation {
                        generation: current.generation + 1,
                        secret: zeroize::Zeroizing::new(call_media_advance(&current.secret[..])?),
                    };
                }
            }
            participants.push(CallMediaParticipant {
                leaf_index: *leaf,
                participant_id: peer.participant_id.clone(),
                session_id: peer.session_id.clone(),
                track_names: peer.track_names.clone(),
                keyed: peer.granted.is_some(),
            });
        }
        Ok(CallMediaKeys {
            epoch,
            own_leaf,
            send_key_index: call_key_index_v2(epoch, own.applied.generation),
            senders,
            participants,
        })
    }

    /// A signed `Joined` opened from `sender_leaf`: bind (or refresh) the
    /// participant. A NEW participant, while this device is in the call, gets
    /// this device's secret advanced one step, alone; the envelopes come back
    /// to send.
    ///
    /// The roster is read first: the device at `sender_leaf` may sit where a
    /// commit removed a participant this device had granted its secret to
    /// (RFC 9420 seats an add at the leftmost blank leaf). That removal owes a
    /// rotation, and an advance for the newcomer must not stand in for it.
    ///
    /// `epoch` is the MLS epoch the `Joined` was sealed in and `mark` the
    /// participation it names: one from an earlier
    /// participation of the device last bound at that leaf is refused
    /// ([`JoinedOrder`]).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn call_media_on_signed_joined(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
        sender_leaf: u32,
        device_id: &str,
        epoch: u64,
        participant_id: &str,
        session_id: &str,
        media_key: &[u8],
        media_key_pq: &[u8],
        mark: Mark,
    ) -> Result<Vec<Vec<u8>>> {
        // A participant names both call keys and no session: its session
        // travels only in grants, and only to its X-Wing key.
        if media_key.is_empty() || media_key_pq.is_empty() || !session_id.is_empty() {
            return Err(Error::invalid(format!(
                "a signed Joined from leaf {sender_leaf} names no post-quantum call key, or its session"
            )));
        }
        let public_key: [u8; CALL_MEDIA_PUBLIC_KEY_BYTES] = media_key
            .try_into()
            .map_err(|_| Error::invalid("a Joined's media key is 32 bytes"))?;
        if !call_media_pq_key_is_valid(media_key_pq) {
            return Err(Error::invalid(format!(
                "a Joined's post-quantum media key is a {CALL_MEDIA_PQ_PUBLIC_KEY_BYTES}-byte X-Wing key no grant can be sealed to"
            )));
        }
        let pq_key = media_key_pq.to_vec();
        let now_ms = self.now_monotonic_ms();
        // Not a member: nothing to bind.
        self.own_leaf(group_id)?;
        self.call_media_prune(group_id, call_id)?;
        if let Some(state) = self.call_media.get(group_id, call_id) {
            // A Joined the server held back past a later participation of the
            // same device (a rejoin after lost state, or under a new id)
            // would re-bind the leaf to a call key that died with the
            // earlier one, or to an id it left: every grant this device sent
            // it after that would go to a key nobody holds.
            if state
                .joined_order
                .get(&sender_leaf)
                .is_some_and(|order| order.device_id == device_id && order.supersedes(epoch, &mark))
            {
                return Err(Error::invalid(format!(
                    "a signed Joined from leaf {sender_leaf} is from an earlier participation of that device than the one bound there"
                )));
            }
            // A keyed participation keeps the id it bound under: a client
            // keys tiles and a `Remove` by id, so a rename would leave the
            // tile a `Remove` names behind while the device stays keyed.
            if state.peers.get(&sender_leaf).is_some_and(|peer| {
                peer.device_id == device_id
                    && peer.public_key == public_key
                    && peer.participant_id != participant_id
            }) {
                return Err(Error::invalid(format!(
                    "a signed Joined from leaf {sender_leaf} names {participant_id}, but a participation keeps its participant id: a new id is a new join"
                )));
            }
            // An id an admin's Remove took out is never bound again: binding
            // it would grant it this device's secret while no client shows it.
            if state.removed.contains(participant_id) {
                return Err(Error::invalid(format!(
                    "a signed Joined from leaf {sender_leaf} names {participant_id}, which was removed from this call"
                )));
            }
            // A participant id is one device's in a call, and the first to
            // bind it keeps it: a client keys tiles and a `Remove` by id, so
            // a second leaf under it would be keyed behind the first's tile.
            let taken = state.own_participant_id() == Some(participant_id)
                || state.peers.iter().any(|(leaf, peer)| {
                    *leaf != sender_leaf && peer.participant_id == participant_id
                });
            if taken {
                return Err(Error::invalid(format!(
                    "a signed Joined from leaf {sender_leaf} names {participant_id}, which another participant in this call holds"
                )));
            }
        }
        let state = self.call_media.entry(group_id, call_id);
        // The same device at this leaf, under the same participant id, with
        // a new call key: it joined again because its core lost the call's
        // state. It binds this device again only from a signed Joined of this
        // device's, and a client answers a newcomer's id once (an id it has
        // seen gets no answer), so the core sends it.
        let returning = state.peers.get(&sender_leaf).is_some_and(|peer| {
            peer.device_id == device_id
                && peer.participant_id == participant_id
                && peer.public_key != public_key
        });
        // Bound from here on: the order of the leaf's latest Joined. The same
        // participation keeps the latest epoch it was seen at.
        let order_epoch = state
            .joined_order
            .get(&sender_leaf)
            .filter(|order| order.device_id == device_id && order.mark.same(&mark))
            .map_or(epoch, |order| order.epoch.max(epoch));
        state.joined_order.insert(
            sender_leaf,
            JoinedOrder {
                device_id: device_id.to_string(),
                epoch: order_epoch,
                mark,
            },
        );
        let newcomer = match state.peers.get_mut(&sender_leaf) {
            Some(peer)
                if peer.device_id == device_id
                    && peer.public_key == public_key
                    && peer.pq_key == pq_key =>
            {
                peer.participant_id = participant_id.to_string();
                peer.mark = mark;
                false
            }
            replaced => {
                // A new participant, another device at this leaf, or the same
                // device joined again with a new key: nothing it was granted
                // before counts. Another device taking a keyed participant's
                // place is a leave for the one it replaces, which holds this
                // device's secret: a rotation is owed, however this leaf came
                // to change hands (the prune above normally owes it already).
                let displaces_keyed = replaced.is_some_and(|peer| peer.device_id != device_id);
                if displaces_keyed && state.own.is_some() {
                    state.rotation_owed = true;
                }
                state.peers.insert(
                    sender_leaf,
                    Peer {
                        device_id: device_id.to_string(),
                        participant_id: participant_id.to_string(),
                        mark,
                        public_key,
                        pq_key: pq_key.clone(),
                        granted: None,
                        announced: 0,
                        previous: None,
                        previous_until_ms: 0,
                        session_id: String::new(),
                        track_names: Vec::new(),
                    },
                );
                true
            }
        };
        // Grants that came before this binding count now: those this
        // participation sealed. Another participation's stay held (a later
        // one's Joined is still to come) until a binding of the leaf drops
        // them: an earlier one's secret is not what the device sends under.
        let held: Vec<Held> = {
            let (mine, rest): (Vec<Held>, Vec<Held>) = std::mem::take(&mut state.held)
                .into_iter()
                .partition(|held| held.sender_leaf == sender_leaf);
            state.held = rest;
            mine
        };
        for held in held {
            // Only from the device bound here.
            if held.device_id != device_id {
                continue;
            }
            if held.mark.same(&mark) {
                if let Some(peer) = state.peers.get_mut(&sender_leaf) {
                    take_grant(peer, held.payload, now_ms)?;
                }
            } else if mark.before(&held.mark) {
                state.held.push(held);
            }
        }
        // To a returning device, which forgot it, this device's own Joined
        // goes out again, signed. Only once this device's own Joined went
        // out: before, that one is still to come.
        let rejoin = if returning {
            self.call_media_own_joined(group_id, call_id)?
        } else {
            None
        };
        let mut send = Vec::new();
        if let Some(rejoin) = rejoin {
            let sealed = self
                .seal_call_signal_on_mls_lane_now(group_id, &rejoin)
                .map(|envelope| vec![envelope]);
            send.extend(self.call_media_owe_on_lapse(group_id, call_id, sealed, Owed::Joined)?);
        }
        if !newcomer {
            return Ok(send);
        }
        let Some(own) = self
            .call_media
            .get_mut(group_id, call_id)
            .and_then(|state| state.own.as_mut())
        else {
            return Ok(send);
        };
        let latest = own.latest().clone();
        let next = Generation {
            generation: latest
                .generation
                .checked_add(1)
                .ok_or_else(|| Error::invalid("this call has run out of media generations"))?,
            secret: zeroize::Zeroizing::new(call_media_advance(&latest.secret[..])?),
        };
        if own.pending.is_some() {
            own.pending = Some(next);
        } else {
            own.applied = next;
        }
        send.extend(self.call_media_seal_grants(
            group_id,
            call_id,
            false,
            &[(sender_leaf, pq_key)],
        )?);
        Ok(send)
    }

    /// A signed `Left` opened from `sender_leaf`, naming `participant_id`:
    /// the participant bound at that leaf is gone, if that device is the one
    /// bound there. The roster is read first, as at every signal. Answers
    /// the envelopes this device owes (the rotation past the leaver) and the
    /// leaf it unbound, if it unbound one.
    ///
    /// A signed `Left` speaks only for its sender's own participant. One that
    /// names this device's own id while it is a v2 participant, a participant
    /// bound at another leaf while its sender's leaf is bound under another
    /// id, or an id another leaf holds while its sender's leaf is unbound, is
    /// refused: a client drops the tile the id names, so such a `Left` would
    /// take a participant off every tile while every core still granted it
    /// each rotation. An accepted one always unlists and rotates out the same
    /// participant, in one event.
    pub(crate) fn call_media_on_signed_left(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
        sender_leaf: u32,
        device_id: &str,
        participant_id: &str,
    ) -> Result<(Vec<Vec<u8>>, Option<u32>)> {
        self.call_media_prune(group_id, call_id)?;
        let Some(state) = self.call_media.get(group_id, call_id) else {
            return Ok((Vec::new(), None));
        };
        if state.own_participant_id() == Some(participant_id) {
            return Err(Error::invalid(format!(
                "a signed Left from leaf {sender_leaf} names {participant_id}, this device's own participant"
            )));
        }
        let speaks_for_its_own = match state.peers.get(&sender_leaf) {
            Some(peer) => peer.participant_id == participant_id,
            None => !state
                .peers
                .values()
                .any(|peer| peer.participant_id == participant_id),
        };
        if !speaks_for_its_own {
            return Err(Error::invalid(format!(
                "a signed Left from leaf {sender_leaf} names {participant_id}, which that leaf does not hold"
            )));
        }
        let bound = state
            .peers
            .get(&sender_leaf)
            .is_some_and(|peer| peer.device_id == device_id);
        if !bound {
            return Ok((Vec::new(), None));
        }
        let send = self.call_media_remove(group_id, call_id, sender_leaf)?;
        Ok((send, Some(sender_leaf)))
    }

    /// A signed `MediaKey` opened from `sender_leaf`. A grant to this device
    /// opens with its call private key and counts only from the device bound
    /// at that leaf (otherwise it is held); an advance granted to somebody
    /// else moves this device's copy on. The roster is read first, as at
    /// every signal.
    ///
    /// Both count only under the participation bound there: a `MediaKey`
    /// naming another participation ([`Mark`]) is not from it. One from an earlier
    /// participation of that device is dropped (its secret is not what the
    /// device sends under now), and a grant from a later one is held until
    /// that participation's `Joined` binds.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn call_media_on_key(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
        sender_leaf: u32,
        device_id: &str,
        generation: u32,
        rotated: bool,
        grants: &[MediaGrant],
        mark: Mark,
    ) -> Result<Option<OpenedMediaGrant>> {
        self.call_media_prune(group_id, call_id)?;
        let own_leaf = self.own_leaf(group_id)?;
        let now_ms = self.now_monotonic_ms();
        let Some(state) = self.call_media.get_mut(group_id, call_id) else {
            return Ok(None);
        };
        let Some(own) = state.own.as_ref() else {
            return Ok(None);
        };
        let bound = state
            .peers
            .get(&sender_leaf)
            .is_some_and(|peer| peer.device_id == device_id && peer.mark.same(&mark));
        let earlier = state
            .joined_order
            .get(&sender_leaf)
            .is_some_and(|order| order.device_id == device_id && mark.before(&order.mark));
        // A grant to this device: the one sealed to its X-Wing key.
        let mine = grants
            .iter()
            .filter(|grant| grant.to_leaf == own_leaf)
            .find(|grant| grant.enc.len() == CALL_MEDIA_PQ_ENC_BYTES);
        let Some(grant) = mine else {
            if bound && !rotated {
                if let Some(peer) = state.peers.get_mut(&sender_leaf) {
                    if let Some(granted) = &peer.granted {
                        if generation > peer.announced
                            && generation - granted.generation <= CALL_MEDIA_MAX_ADVANCE
                        {
                            peer.announced = generation;
                        }
                    }
                }
            }
            return Ok(None);
        };
        let Ok(payload) = open_call_media_grant_any(
            &own.pq_private_key,
            call_id,
            sender_leaf,
            own_leaf,
            &grant.enc,
            &grant.ciphertext,
        ) else {
            // Sealed to a key this device no longer holds (it joined again),
            // or not for it at all: nothing to take.
            return Ok(None);
        };
        if payload.generation != generation {
            return Err(Error::invalid(
                "a media grant's generation is not its signal's",
            ));
        }
        if earlier && !bound {
            // An earlier participation's secret: nothing to take.
            return Ok(None);
        }
        let opened = OpenedMediaGrant {
            sender_leaf,
            generation,
            session_id: payload.session_id.clone(),
            track_names: payload.track_names.clone(),
            bound,
        };
        if bound {
            if let Some(peer) = state.peers.get_mut(&sender_leaf) {
                take_grant(peer, payload, now_ms)?;
            }
        } else {
            if state.held.len() >= MAX_HELD_GRANTS {
                state.held.remove(0);
            }
            state.held.push(Held {
                sender_leaf,
                device_id: device_id.to_string(),
                mark,
                payload,
            });
        }
        Ok(Some(opened))
    }

    /// [`Client::call_media_start`], [`Client::call_media_share`], [`Client::call_media_remove`],
    /// [`Client::call_media_on_epoch`], [`Client::call_media_apply`],
    /// [`Client::call_media_end`] and [`Client::call_media_keys`] through one
    /// JSON door, the one the bindings cross:
    ///
    /// | `op` | needs | answers |
    /// | --- | --- | --- |
    /// | `start` | `callId`, `participantId`, `sessionId`, `trackNames` | `{"mediaKeyHex"}` |
    /// | `share` | `callId` | `{"send":[hex…]}` |
    /// | `remove` | `callId`, `participantId` or `leafIndex` | `{"send":[hex…]}` |
    /// | `epoch` | `callId` | `{"send":[hex…]}` |
    /// | `apply` | `callId` | `{"send":[hex…]}` |
    /// | `end` | `callId` | `{}` |
    /// | `keys` | `callId`, `pending`? | [`CallMediaKeys`] as JSON |
    ///
    /// `keys`, like sealing a `Joined`, fails with [`CALL_STATE_LOST`] in its
    /// message when this core holds no participation in the call: a client
    /// that believes it is in the call joins again (`start` under the id it
    /// holds, a signed `Joined`, `share`).
    ///
    /// Every answer but `start`'s and `end`'s also carries `applyAfterMs`
    /// (ms until a pending rotation switches, null when none is pending) and
    /// `applied` (the core switched this device's sending key since a door
    /// last said so: reload `keys`). Each `send` entry is a whole kind-6
    /// envelope for `SendSealed`, not urgent, in order.
    pub fn call_media_json(&mut self, group_id: &[u8], request_json: &str) -> Result<String> {
        let request: Value = serde_json::from_str(request_json).map_err(|err| {
            Error::invalid(format!("could not read the call media request: {err}"))
        })?;
        let op = request
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::invalid("a call media request needs an `op`"))?;
        let call_id = from_hex(
            request
                .get("callId")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::invalid("a call media request needs a `callId`"))?,
            "callId",
        )?;
        let hexes = |envelopes: Vec<Vec<u8>>| -> Vec<String> {
            envelopes.iter().map(|bytes| to_hex(bytes)).collect()
        };
        let answer = match op {
            "start" => {
                let participant_id = request
                    .get("participantId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::invalid("`start` needs a `participantId`"))?;
                let session_id = request
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::invalid("`start` needs a `sessionId`"))?;
                let track_names: Vec<String> = match request.get("trackNames") {
                    Some(value) => serde_json::from_value(value.clone())
                        .map_err(|_| Error::invalid("`trackNames` is a list of strings"))?,
                    None => Vec::new(),
                };
                let key = self.call_media_start(
                    group_id,
                    &call_id,
                    participant_id,
                    session_id,
                    &track_names,
                )?;
                json!({ "mediaKeyHex": to_hex(&key) })
            }
            "share" => json!({ "send": hexes(self.call_media_share(group_id, &call_id)?) }),
            "remove" => {
                // An honored Remove names the participant; a stale one, its leaf.
                let send = match request.get("participantId").and_then(Value::as_str) {
                    Some(participant_id) => {
                        self.call_media_remove_participant(group_id, &call_id, participant_id)?
                    }
                    None => {
                        let leaf = request
                            .get("leafIndex")
                            .and_then(Value::as_u64)
                            .and_then(|v| u32::try_from(v).ok())
                            .ok_or_else(|| {
                                Error::invalid(
                                    "`remove` needs a u32 `leafIndex` or a `participantId`",
                                )
                            })?;
                        self.call_media_remove(group_id, &call_id, leaf)?
                    }
                };
                json!({ "send": hexes(send) })
            }
            "epoch" => {
                let rotation = self.call_media_on_epoch(group_id, &call_id)?;
                json!({ "send": hexes(rotation.unwrap_or_default()) })
            }
            "apply" => json!({ "send": hexes(self.call_media_apply(group_id, &call_id)?) }),
            "end" => {
                self.call_media_end(group_id, &call_id)?;
                json!({})
            }
            "keys" => {
                let pending = request
                    .get("pending")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                self.call_media_keys(group_id, &call_id, pending)?.to_json()
            }
            other => {
                return Err(Error::invalid(format!(
                    "unknown call media op {other:?}; known: start, share, remove, epoch, apply, end, keys"
                )))
            }
        };
        // `keys` spells each sender key in hex: the answer's strings are
        // wiped when it drops, on every return.
        let mut answer = WipedValue(answer);
        // Every answer but `start`'s and `end`'s says whether a rotation is
        // pending and when it switches (the same due time at every door,
        // whichever door drew it), and whether the core switched this
        // device's sending key since a door last said so.
        if !matches!(op, "start" | "end") {
            let checked = check_call_id(&call_id)?;
            let applied = self.call_media_take_applied(group_id, &checked);
            let after = self.call_media_apply_after_ms(group_id, &call_id);
            if let Value::Object(map) = &mut answer.0 {
                map.insert("applyAfterMs".into(), json!(after));
                map.insert("applied".into(), json!(applied));
            }
        }
        to_string_unspilled(&answer.0)
    }
}

/// A JSON value whose strings are wiped when it drops.
struct WipedValue(Value);

impl Drop for WipedValue {
    fn drop(&mut self) {
        wipe_strings(&mut self.0);
    }
}

/// `value` as JSON text in a buffer sized before the first write, so no
/// reallocation leaves a copy of what it holds behind: the length is counted
/// in a first pass that writes nothing. On a refusal the bytes written so
/// far are wiped.
fn to_string_unspilled(value: &Value) -> Result<String> {
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
    let refused =
        |err: serde_json::Error| Error::invalid(format!("could not write the answer: {err}"));
    let mut counting = Counting(0);
    serde_json::to_writer(&mut counting, value).map_err(refused)?;
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(counting.0));
    serde_json::to_writer(&mut *out, value).map_err(refused)?;
    String::from_utf8(std::mem::take(&mut *out)).map_err(|err| {
        zeroize::Zeroize::zeroize(&mut err.into_bytes());
        Error::invalid("could not write the answer: it is not UTF-8")
    })
}

/// Wipe every string in `value`, wherever it sits.
fn wipe_strings(value: &mut Value) {
    match value {
        Value::String(text) => zeroize::Zeroize::zeroize(text),
        Value::Array(items) => items.iter_mut().for_each(wipe_strings),
        Value::Object(map) => map.values_mut().for_each(wipe_strings),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Push onto a vector of values that wipe themselves when dropped. When it
/// is full, the items are cloned into a larger buffer and the old ones
/// dropped, each wiping itself, where a reallocation would free the old
/// buffer with the items' bytes still in it.
fn push_wiping<T: Clone>(items: &mut Vec<T>, item: T) {
    if items.len() == items.capacity() {
        let mut grown = Vec::with_capacity(items.capacity().max(2) * 2);
        grown.extend(items.iter().cloned());
        *items = grown;
    }
    items.push(item);
}

/// The peer's secret at the generation it announced last, from the one it
/// granted: the secret it sends under now, unless it has rotated since.
fn current_of(peer: &Peer) -> Result<Option<Generation>> {
    let Some(granted) = &peer.granted else {
        return Ok(None);
    };
    let mut current = granted.clone();
    while current.generation < peer.announced {
        current = Generation {
            generation: current.generation + 1,
            secret: zeroize::Zeroizing::new(call_media_advance(&current.secret[..])?),
        };
    }
    Ok(Some(current))
}

/// Take a grant into a bound peer: a later generation than the one held
/// replaces it (generations only rise per participant and call). The secret
/// it replaces stays for the rotation delay and the key grace, for frames the
/// peer sends before it switches.
fn take_grant(peer: &mut Peer, payload: MediaGrantPayload, now_ms: u64) -> Result<()> {
    let newer = peer
        .granted
        .as_ref()
        .is_none_or(|granted| payload.generation > granted.generation);
    if newer {
        if let Some(current) = current_of(peer)? {
            if current.generation < payload.generation {
                peer.previous = Some(current);
                peer.previous_until_ms = now_ms
                    .saturating_add(CALL_MEDIA_ROTATE_DELAY_MS)
                    .saturating_add(super::CALL_KEY_GRACE_MS);
            }
        }
        peer.announced = peer.announced.max(payload.generation);
        peer.granted = Some(Generation {
            generation: payload.generation,
            secret: zeroize::Zeroizing::new(*payload.secret),
        });
        peer.session_id = payload.session_id;
        peer.track_names = payload.track_names;
    }
    Ok(())
}

impl CallMediaKeys {
    /// `{"epoch","ownLeaf","sendKeyIndex","senders":[{"leafIndex","generation",
    /// "keyIndex","senderKeyHex"}],"participants":[{"leafIndex","participantId",
    /// "sessionId","trackNames","keyed"}]}`.
    ///
    /// Each `senderKeyHex` string is moved into the answer, never copied
    /// (`json!` copies what it is handed), so wiping the answer's strings
    /// wipes every copy of the keys it spells.
    pub fn to_json(&self) -> Value {
        let mut senders = Vec::with_capacity(self.senders.len());
        for key in &self.senders {
            let mut entry = serde_json::Map::new();
            entry.insert("leafIndex".into(), key.leaf_index.into());
            entry.insert("generation".into(), key.generation.into());
            entry.insert("keyIndex".into(), key.key_index.into());
            entry.insert("senderKeyHex".into(), Value::String(to_hex(&key.key[..])));
            senders.push(Value::Object(entry));
        }
        let mut answer = json!({
            "epoch": self.epoch,
            "ownLeaf": self.own_leaf,
            "sendKeyIndex": self.send_key_index,
            "participants": self.participants.iter().map(|p| json!({
                "leafIndex": p.leaf_index,
                "participantId": p.participant_id,
                "sessionId": p.session_id,
                "trackNames": p.track_names,
                "keyed": p.keyed,
            })).collect::<Vec<_>>(),
        });
        if let Value::Object(map) = &mut answer {
            map.insert("senders".into(), Value::Array(senders));
        }
        answer
    }
}
