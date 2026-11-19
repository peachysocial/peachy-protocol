// SPDX-License-Identifier: MIT
//! The [`Client`] doors a call goes through: the epoch's key ring, and
//! sealing and opening a call envelope (docs/calls.md §Keys,
//! §Signaling).

use openmls::prelude::{ContentType, MlsMessageIn};
use tls_codec::Deserialize as _;

use super::frame::{
    live_signature_holds, live_signature_statement, open_live_frame, seal_live_frame, CallLane,
    LiveStamp, CALL_LANE_MLS,
};
use super::keys::{call_key_index, call_sender_key, CALL_EXPORTER_LABEL, CALL_ROOT_BYTES};
use super::media::Mark;
use super::signal::{
    append_live_signature, decode_call_signal, encode_call_signal, split_live_signature,
    CallSignal, CallSignalBody, Participation, CALL_ID_BYTES, CALL_LIVE_SIGNATURE_BYTES,
};
use super::{CALL_LIVE_EXPORTER_LABEL, CALL_LIVE_KEY_BYTES, CALL_SENDER_KEY_BYTES};
use crate::envelope::ENVELOPE_KIND_CALL;
use crate::error::{Error, Result};
use crate::group::{Client, Incoming};
use crate::identity::PeachyIdentity;
use crate::secret::Secret;

/// One sender's frame-encryption key for one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSenderKey {
    pub leaf_index: u32,
    pub key: Secret<[u8; CALL_SENDER_KEY_BYTES]>,
}

/// A call's keys at one epoch: what a client loads into its frame encryptor's
/// key provider, each sender's key at slot `key_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallKeys {
    pub epoch: u64,
    pub key_index: u8,
    /// `MLS-Exporter(G, "peachy call v1", call_id, 32)` at `epoch`. A sender
    /// that is not in `senders` (a leaf a staged commit adds) derives with
    /// [`super::call_sender_key`].
    pub call_root: Secret<[u8; CALL_ROOT_BYTES]>,
    /// Every leaf in the group's tree, in leaf order.
    pub senders: Vec<CallSenderKey>,
}

/// A call envelope's signal, opened. Its `Debug` leaves out what the signal
/// says.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenedCallSignal {
    pub lane: CallLane,
    /// Who sent it: the MLS lane's authenticated sender. `None` on the live
    /// lane, whose frame is signed by the leaf it claims but names no sender
    /// a client binds (see [`super::frame`]).
    pub sender: Option<PeachyIdentity>,
    /// The sender's leaf index, on the MLS lane.
    pub sender_leaf: Option<u32>,
    pub signal: CallSignal,
    /// Envelopes this device must send now (`SendSealed`, not urgent, in
    /// order): the grants a v2 participant owes a newcomer's signed `Joined`
    /// or a leaver's signed `Left` (docs/calls.md §Participant media
    /// keys). Empty otherwise.
    pub send: Vec<Vec<u8>>,
    /// What a `MediaKey` granted this device, if anything. Reload the keys
    /// ([`Client::call_media_keys`]) after any v2 signal opens.
    pub media: Option<super::OpenedMediaGrant>,
    /// The leaf a signed `Left` unbound here: its sender's own, bound under
    /// the id the `Left` names. `None` when it unbound nothing (this device
    /// never bound that leaf), and for every other signal. A client drops a
    /// tile for a signed `Left` only when this names the leaf the tile is at
    /// (docs/calls.md R-K10).
    pub unbound_leaf: Option<u32>,
    /// While this device has a rotation pending in the signal's call: the
    /// milliseconds until the core switches its sending key to it (by
    /// itself, at the first door call at or after then). `None` otherwise.
    pub apply_after_ms: Option<u64>,
    /// The core switched this device's sending key in the signal's call
    /// since a door last said so: reload the keys.
    pub applied: bool,
}

impl std::fmt::Debug for OpenedCallSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedCallSignal")
            .field("lane", &self.lane)
            .field("sender", &self.sender)
            .field("sender_leaf", &self.sender_leaf)
            .field("signal_version", &self.signal.version)
            .field("send_len", &self.send.len())
            .field("media", &self.media.is_some())
            .field("unbound_leaf", &self.unbound_leaf)
            .field("apply_after_ms", &self.apply_after_ms)
            .field("applied", &self.applied)
            .finish_non_exhaustive()
    }
}

/// A signed `Joined` or `MediaKey`'s participation mark, which every build
/// sends: one without it is refused, since nothing else orders a device's
/// participations.
fn marked(participation: Option<Participation>) -> Result<Participation> {
    participation.ok_or_else(|| {
        Error::invalid("a signed Joined or MediaKey carries its participation's mark")
    })
}

fn check_call_id(call_id: &[u8]) -> Result<()> {
    if call_id.len() != CALL_ID_BYTES {
        return Err(Error::invalid(format!(
            "a call id is {CALL_ID_BYTES} bytes, not {}",
            call_id.len()
        )));
    }
    Ok(())
}

fn keys_from_root(
    epoch: u64,
    root: zeroize::Zeroizing<Vec<u8>>,
    leaves: &[u32],
) -> Result<CallKeys> {
    let mut keys = CallKeys {
        epoch,
        key_index: call_key_index(epoch),
        call_root: Secret::new(
            root.as_slice()
                .try_into()
                .map_err(|_| Error::invalid("the exporter returned the wrong length"))?,
        ),
        // Sized before the first push, so no reallocation leaves a key
        // behind; on an error return the keys wipe themselves.
        senders: Vec::with_capacity(leaves.len()),
    };
    for leaf in leaves {
        let key = call_sender_key(&keys.call_root[..], *leaf)?;
        keys.senders.push(CallSenderKey {
            leaf_index: *leaf,
            key: key.into(),
        });
    }
    Ok(keys)
}

/// What this device's own `Joined` or `Left` does to its call state, applied
/// only once the signal is sealed.
pub(crate) enum OwnEffect {
    Nothing,
    /// Its participation ends: its media keys.
    Ends,
}

impl OwnEffect {
    fn ends_if(ends: bool) -> Self {
        if ends {
            Self::Ends
        } else {
            Self::Nothing
        }
    }
}

impl Client {
    /// Who may have signed a live frame claiming `leaf`: `None` when the
    /// tree holds no leaf there, else the leaf's signature key when its
    /// credential checks out. Only that one credential is validated, so a
    /// frame the server repeats, refused at the replay check, costs one
    /// credential check and one signature, whatever the group's size.
    fn live_signer_at(&self, group_id: &[u8], leaf: u32) -> Result<Option<Option<Vec<u8>>>> {
        Ok(self
            .roster_entry_at(group_id, leaf)?
            .map(|entry| entry.identity.is_ok().then_some(entry.leaf_key)))
    }

    fn leaf_indices(&self, group_id: &[u8]) -> Result<Vec<u32>> {
        Ok(self
            .roster(group_id)?
            .into_iter()
            .map(|entry| entry.leaf_index)
            .collect())
    }

    /// The call's keys at the group's CURRENT epoch. Called again after every
    /// epoch change; the client keeps the previous ring for
    /// [`super::CALL_KEY_GRACE_MS`].
    pub fn call_keys(&self, group_id: &[u8], call_id: &[u8]) -> Result<CallKeys> {
        check_call_id(call_id)?;
        let epoch = self.epoch(group_id)?;
        // Everything that can fail is asked first: once the root is
        // exported, it goes straight into the value that wipes it.
        let leaves = self.leaf_indices(group_id)?;
        let root = zeroize::Zeroizing::new(self.export_secret(
            group_id,
            CALL_EXPORTER_LABEL,
            call_id,
            CALL_ROOT_BYTES,
        )?);
        keys_from_root(epoch, root, &leaves)
    }

    /// The call's keys at the epoch this device's STAGED commit would move
    /// the group to, before the merge — so a committer can load `e+1` before
    /// the first frame under it arrives. `senders` lists the CURRENT tree's
    /// leaves; a leaf the commit adds derives from `call_root`.
    pub fn pending_call_keys(&self, group_id: &[u8], call_id: &[u8]) -> Result<CallKeys> {
        check_call_id(call_id)?;
        let epoch = self.epoch(group_id)?.saturating_add(1);
        // As in `call_keys`: nothing fallible between the export and the
        // value that wipes it.
        let leaves = self.leaf_indices(group_id)?;
        let root = zeroize::Zeroizing::new(self.export_pending_secret(
            group_id,
            CALL_EXPORTER_LABEL,
            call_id,
            CALL_ROOT_BYTES,
        )?);
        keys_from_root(epoch, root, &leaves)
    }

    fn live_key(&self, group_id: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.export_secret(group_id, CALL_LIVE_EXPORTER_LABEL, &[], CALL_LIVE_KEY_BYTES)
            .map(zeroize::Zeroizing::new)
    }

    /// Seal a call signal for `group_id`: the whole envelope, ready for
    /// `SendSealed`. The lane follows from the signal's type
    /// ([`super::CallSignalBody::is_mls_lane`]): `Offer`, `Answer`, `Hangup`,
    /// `Remove`, `Direct` and the in-call controls as an MLS application
    /// message (this advances the sender ratchet and persists, like
    /// [`Client::encrypt`]) whose authenticated data is
    /// [`super::CALL_LANE_AAD`], so that it is as long as a message of the
    /// same padding block, and `Joined` as a live frame. A
    /// participant's first `Joined` per epoch must be signed although its
    /// type would go live, so it goes through
    /// [`Client::seal_call_signal_on_mls_lane`] instead.
    ///
    /// For a v2 participant ([`Client::call_media_start`]) a `Joined` carries
    /// the device's call public key and never its media-server session or
    /// tracks (those go only in grants). A `Joined` from a device that is
    /// not a participant (its core lost the call's state, or the client
    /// never asked `start`) is refused with [`super::CALL_STATE_LOST`].
    /// Every `Left` goes signed, so
    /// the participants that remain rotate whatever this core remembers. A
    /// `Left` naming the participant id `start` named also makes the device
    /// forget the call's media keys; any other (a rejoin's old one, sent
    /// before or after `start`) leaves them alone.
    ///
    /// A rotation of this device's media secret that is due switches here
    /// first (docs/calls.md §Leaving): a call's heartbeat seals
    /// every 10 s, so the switch never waits on the client.
    pub fn seal_call_signal(&mut self, group_id: &[u8], signal: &CallSignal) -> Result<Vec<u8>> {
        self.call_media_promote_due(group_id, &signal.call_id, false)?;
        let signed = signal.body.is_mls_lane();
        let (signal, force_signed, effect) = self.call_media_outgoing(group_id, signal, signed)?;
        if force_signed {
            return self.seal_call_signal_on_mls_lane_now(group_id, &signal);
        }
        let signal = &signal;
        let encoded = encode_call_signal(signal)?;
        let inner = if signal.body.is_mls_lane() {
            let message = self.encrypt_call_signal(group_id, &encoded)?;
            let mut inner = Vec::with_capacity(1 + message.len());
            inner.push(CALL_LANE_MLS);
            inner.extend_from_slice(&message);
            inner
        } else {
            let key = self.live_key(group_id)?;
            let epoch = self.epoch(group_id)?;
            let stamp = self.next_live_stamp(group_id)?;
            let signature = self
                .sign_with_own_leaf(&live_signature_statement(group_id, epoch, stamp, &encoded))?;
            let signature = <[u8; CALL_LIVE_SIGNATURE_BYTES]>::try_from(signature.as_slice())
                .map_err(|_| {
                    Error::Mls(format!(
                        "a live call signature came back {} bytes long",
                        signature.len()
                    ))
                })?;
            let mut signed = encoded;
            append_live_signature(&mut signed, &signature);
            seal_live_frame(&key, stamp, &signed)?
        };
        let envelope = self.seal_envelope(group_id, ENVELOPE_KIND_CALL, &inner)?;
        // Only an unsigned signal comes here: a `Joined`, whose sealing
        // changes nothing.
        self.apply_own_effect(group_id, signal, effect);
        Ok(envelope)
    }

    /// The stamp for this device's next live frame: its own leaf, and its
    /// clock in milliseconds made strictly increasing
    /// (docs/calls.md D3; [`super::replay`]).
    fn next_live_stamp(&mut self, group_id: &[u8]) -> Result<LiveStamp> {
        let sender_leaf = self.own_leaf(group_id)?;
        let sent_at_ms = self
            .now_unix_ms()
            .max(self.live_last_sent_ms.saturating_add(1));
        self.live_last_sent_ms = sent_at_ms;
        Ok(LiveStamp {
            sender_leaf,
            sent_at_ms,
        })
    }

    /// Open a call envelope's inner bytes (what [`Client::open_envelope`]
    /// returned for kind [`ENVELOPE_KIND_CALL`]).
    ///
    /// On the MLS lane the message must be an APPLICATION message — a commit
    /// or proposal wrapped as a call is refused before OpenMLS touches it, so
    /// a call envelope can never move the group. Any signal type may come
    /// signed; a signed `Joined` must name its sender's own leaf (and, with a
    /// call key, the participant id its participation is bound under here),
    /// and a signed `Left` its sender's own participant (not this
    /// device's own id
    /// while it is a v2 participant, not an id another leaf holds, and not
    /// another id than the one its sender's leaf is bound under). A device's
    /// own signal coming back is refused as an echo. On the live lane every
    /// body [`super::CallSignalBody::is_mls_lane`] lists, and every body this
    /// build does not know, is refused, so a live frame cannot ring, hang up, remove, set up a direct
    /// call or speak for a participant; a frame claiming a leaf the tree does
    /// not hold is refused; a live `Joined` must name the leaf its frame
    /// claims (a member's own core always claims its own); a live `Left` is
    /// refused, since every `Left` goes signed; and a live frame must pass this client's replay window
    /// ([`super::replay`], threat model D3): a stamp already seen, behind the
    /// window, or more than [`super::CALL_LIVE_MAX_SKEW_MS`] from this
    /// client's clock is refused as a replay. A signal of a type this build
    /// does not know opens as [`super::CallSignalBody::Unknown`] on the MLS
    /// lane only.
    pub fn open_call_signal(&mut self, group_id: &[u8], inner: &[u8]) -> Result<OpenedCallSignal> {
        let (lane, rest) = CallLane::split(inner)?;
        match lane {
            CallLane::Mls => {
                let message = MlsMessageIn::tls_deserialize_exact(rest)?;
                let protocol = message
                    .try_into_protocol_message()
                    .map_err(|_| Error::invalid("a call envelope carries a group message"))?;
                if protocol.content_type() != ContentType::Application {
                    return Err(Error::invalid(
                        "a call envelope carries only an application message",
                    ));
                }
                // The epoch it was sealed in, which MLS authenticates: it
                // orders one device's participations (a signed Joined).
                let sealed_epoch = protocol.epoch().as_u64();
                match self.process_message(group_id, rest)? {
                    Incoming::Application {
                        sender, plaintext, ..
                    } => {
                        let signal = decode_call_signal(&plaintext)?;
                        // Any signal may come signed (a participant's first
                        // `Joined` does, threat model D10); authentication
                        // only adds. A signed `Joined` binds its sender's
                        // tracks to a leaf, so it must name the sender's OWN
                        // leaf.
                        let sender_leaf = self.leaf_of_device(group_id, &sender.device_id)?;
                        if let super::CallSignalBody::Joined { leaf_index, .. } = &signal.body {
                            if *leaf_index != sender_leaf {
                                return Err(Error::invalid(format!(
                                    "a signed Joined names leaf {leaf_index}, but its sender is leaf {sender_leaf}"
                                )));
                            }
                        }
                        // Participant media keys: only a SIGNED Joined binds
                        // a participant, only a signed Left from the device
                        // bound there rotates, and a MediaKey counts only
                        // from that device. The signal is taken already, so
                        // what this device owes in return and cannot seal on
                        // a lapsed leaf is owed, not a reason to drop it.
                        let (send, media, unbound_leaf, apply_after_ms, applied) = self
                            .call_media_deferring_lapsed_seals(|client| {
                                let mut send = Vec::new();
                                let mut media = None;
                                let mut unbound_leaf = None;
                                match &signal.body {
                                    CallSignalBody::Joined {
                                        participant_id,
                                        session_id,
                                        media_key,
                                        started_at_ms,
                                        media_key_pq,
                                        participation,
                                        ..
                                    } => {
                                        send = client.call_media_on_signed_joined(
                                            group_id,
                                            &signal.call_id,
                                            sender_leaf,
                                            &sender.device_id,
                                            sealed_epoch,
                                            participant_id,
                                            session_id,
                                            media_key,
                                            media_key_pq,
                                            Mark {
                                                started_at_ms: *started_at_ms,
                                                participation: marked(*participation)?,
                                            },
                                        )?;
                                    }
                                    CallSignalBody::Left { participant_id } => {
                                        (send, unbound_leaf) = client.call_media_on_signed_left(
                                            group_id,
                                            &signal.call_id,
                                            sender_leaf,
                                            &sender.device_id,
                                            participant_id,
                                        )?;
                                    }
                                    CallSignalBody::MediaKey {
                                        generation,
                                        rotated,
                                        grants,
                                        started_at_ms,
                                        participation,
                                    } => {
                                        media = client.call_media_on_key(
                                            group_id,
                                            &signal.call_id,
                                            sender_leaf,
                                            &sender.device_id,
                                            *generation,
                                            *rotated,
                                            grants,
                                            Mark {
                                                started_at_ms: *started_at_ms,
                                                participation: marked(*participation)?,
                                            },
                                        )?;
                                    }
                                    _ => {}
                                }
                                let (chained, apply_after_ms, applied) =
                                    client.call_media_after_open(group_id, &signal.call_id)?;
                                send.extend(chained);
                                Ok((send, media, unbound_leaf, apply_after_ms, applied))
                            })?;
                        Ok(OpenedCallSignal {
                            lane,
                            sender: Some(sender),
                            sender_leaf: Some(sender_leaf),
                            signal,
                            send,
                            media,
                            unbound_leaf,
                            apply_after_ms,
                            applied,
                        })
                    }
                    Incoming::Echo => Err(Error::invalid("this device sent that call signal")),
                    _ => Err(Error::invalid(
                        "a call envelope carries only an application message",
                    )),
                }
            }
            CallLane::Live => {
                let (stamp, plaintext) = open_live_frame(&self.live_key(group_id)?, inner)?;
                let (unsigned, signature) = split_live_signature(&plaintext)?;
                let signal = decode_call_signal(unsigned)?;
                if signal.body.is_mls_lane() || matches!(signal.body, CallSignalBody::Unknown) {
                    return Err(Error::invalid(
                        "that call signal must come on the MLS lane, signed by its sender",
                    ));
                }
                // The claimed leaf names whose replay window the stamp is
                // checked in; one the tree does not hold is nobody's.
                let Some(signer) = self.live_signer_at(group_id, stamp.sender_leaf)? else {
                    return Err(Error::invalid(format!(
                        "a live call signal claims leaf {}, which is not in the tree",
                        stamp.sender_leaf
                    )));
                };
                // The leaf's signature (docs/calls.md §The live
                // lane's signature): every live frame must carry one, and it
                // must verify under the key of the leaf the frame claims.
                let epoch = self.epoch(group_id)?;
                let Some(signature) = signature else {
                    return Err(Error::invalid(format!(
                        "a live call signal claiming leaf {} carries no signature",
                        stamp.sender_leaf
                    )));
                };
                let Some(key) = signer else {
                    return Err(Error::invalid(format!(
                        "a signed live call signal claims leaf {}, whose credential does not check out",
                        stamp.sender_leaf
                    )));
                };
                if !live_signature_holds(&key, group_id, epoch, stamp, unsigned, &signature) {
                    return Err(Error::invalid(format!(
                        "a live call signal's signature does not hold for leaf {}",
                        stamp.sender_leaf
                    )));
                }
                // The replay check, as soon as the frame is known to be the
                // claimed leaf's own and before anything reads the whole
                // tree: a frame the server repeats is refused here, having
                // cost one credential check and one signature. A frame its
                // leaf signed that a check below refuses is recorded as seen
                // too, which costs its sender nothing an honest one sends.
                let now_ms = self.now_unix_ms();
                let mono_ms = self.now_monotonic_ms();
                self.live_replay
                    .check(
                        group_id,
                        signal.call_id,
                        epoch,
                        stamp.sender_leaf,
                        stamp.sent_at_ms,
                        now_ms,
                        mono_ms,
                    )
                    .into_result()?;
                // A heartbeat speaks for the leaf its frame claims. Naming
                // another leaf is a heartbeat for someone else's tile, and so
                // is naming this device's own id or a participant bound at
                // another leaf, as the live `Left` below holds.
                if let super::CallSignalBody::Joined {
                    leaf_index,
                    participant_id,
                    ..
                } = &signal.body
                {
                    if *leaf_index != stamp.sender_leaf {
                        return Err(Error::invalid(format!(
                            "a live Joined names leaf {leaf_index}, but its frame claims leaf {}",
                            stamp.sender_leaf
                        )));
                    }
                    // Against the bindings the tree still holds, as every
                    // MLS-lane door reads them: a participant whose leaf a
                    // commit gave to another device is no longer bound.
                    self.call_media_prune(group_id, &signal.call_id)?;
                    if self.call_media.live_joined_names_another(
                        group_id,
                        &signal.call_id,
                        participant_id,
                        stamp.sender_leaf,
                    ) {
                        return Err(Error::invalid(format!(
                            "a live Joined names {participant_id}, this device or bound at another leaf than its frame claims"
                        )));
                    }
                }
                // Every Left goes signed (sealing a participant's ends that
                // device's keys): a live one is never a participant's own,
                // and honored, it would hide a participant every core still
                // grants each rotation to.
                if let CallSignalBody::Left { participant_id } = &signal.body {
                    return Err(Error::invalid(format!(
                        "a live Left names {participant_id}: a Left comes signed, on the MLS lane"
                    )));
                }
                // A heartbeat opened is a door too: a due rotation switches
                // here, at the latest one heartbeat after it is due, and
                // grants owed from a lapsed leaf go once it renewed.
                let (send, apply_after_ms, applied) =
                    self.call_media_deferring_lapsed_seals(|client| {
                        client.call_media_after_open(group_id, &signal.call_id)
                    })?;
                Ok(OpenedCallSignal {
                    lane,
                    sender: None,
                    sender_leaf: None,
                    signal,
                    send,
                    media: None,
                    unbound_leaf: None,
                    apply_after_ms,
                    applied,
                })
            }
        }
    }

    /// What every signal this device opens ends with, once it opened: the
    /// due switch of a pending rotation and any rotation chained after it
    /// (its grants, to send after the open's own), when the pending one
    /// switches, and whether the core switched since a door last said so.
    /// Run after the signal is taken, so a refused one draws nothing whose
    /// grants would be lost with the error.
    fn call_media_after_open(
        &mut self,
        group_id: &[u8],
        call_id: &[u8; CALL_ID_BYTES],
    ) -> Result<(Vec<Vec<u8>>, Option<u64>, bool)> {
        if !self.call_media.is_participant(group_id, call_id) {
            return Ok((Vec::new(), None, false));
        }
        let chained = self.call_media_door(group_id, call_id)?;
        let applied = self.call_media_take_applied(group_id, call_id);
        let after = self.call_media_apply_after_ms(group_id, call_id);
        Ok((chained, after, applied))
    }

    /// Seal any call signal on the MLS lane, sender-authenticated, whatever
    /// its type: a participant's FIRST `Joined` in each epoch goes this way,
    /// so receivers bind its tracks to the sender's own leaf
    /// (docs/calls.md §Disagreements, D10). Every body
    /// [`Client::seal_call_signal`] already signs comes out the same here,
    /// with the same [`super::CALL_LANE_AAD`].
    /// Send it through `SendSealed`, not urgent. A due rotation switches
    /// here first, as in [`Client::seal_call_signal`].
    pub fn seal_call_signal_on_mls_lane(
        &mut self,
        group_id: &[u8],
        signal: &CallSignal,
    ) -> Result<Vec<u8>> {
        self.call_media_promote_due(group_id, &signal.call_id, false)?;
        self.seal_call_signal_on_mls_lane_now(group_id, signal)
    }

    /// [`Client::seal_call_signal_on_mls_lane`] without the due switch: for
    /// the signals the core seals itself while a door runs (grants, a
    /// re-sent `Joined`).
    pub(crate) fn seal_call_signal_on_mls_lane_now(
        &mut self,
        group_id: &[u8],
        signal: &CallSignal,
    ) -> Result<Vec<u8>> {
        let (signal, _, effect) = self.call_media_outgoing(group_id, signal, true)?;
        let encoded = encode_call_signal(&signal)?;
        let message = self.encrypt_call_signal(group_id, &encoded)?;
        let mut inner = Vec::with_capacity(1 + message.len());
        inner.push(CALL_LANE_MLS);
        inner.extend_from_slice(&message);
        let envelope = self.seal_envelope(group_id, ENVELOPE_KIND_CALL, &inner)?;
        self.apply_own_effect(group_id, &signal, effect);
        Ok(envelope)
    }

    /// `signal` sealed on the MLS lane exactly as written, whatever this
    /// device's call state: what a device running its own code sends. A test
    /// door and nothing else, behind `fixture` and exported through no
    /// binding: it lets a test show what receivers do with a signed signal
    /// the honest core would never seal.
    #[cfg(feature = "fixture")]
    #[doc(hidden)]
    pub fn seal_call_signal_as_written(
        &mut self,
        group_id: &[u8],
        signal: &CallSignal,
    ) -> Result<Vec<u8>> {
        let encoded = encode_call_signal(signal)?;
        let message = self.encrypt_call_signal(group_id, &encoded)?;
        let mut inner = Vec::with_capacity(1 + message.len());
        inner.push(CALL_LANE_MLS);
        inner.extend_from_slice(&message);
        self.seal_envelope(group_id, ENVELOPE_KIND_CALL, &inner)
    }

    /// What this device's own sealed `Joined` or `Left` does to its call
    /// state, applied only once the signal is sealed: one that failed to seal
    /// leaves the participation as peers still see it.
    fn apply_own_effect(&mut self, group_id: &[u8], signal: &CallSignal, effect: OwnEffect) {
        match effect {
            OwnEffect::Nothing => {}
            OwnEffect::Ends => {
                if self.call_media.is_participant(group_id, &signal.call_id) {
                    self.call_media_end_by_own_left(group_id, &signal.call_id);
                }
            }
        }
    }

    /// This device's own `Joined` and `Left`, as they go out. A v2
    /// participant's `Joined` names its call public key (and, `signed`, its
    /// X-Wing one: only a signed `Joined` binds, and a live heartbeat stays
    /// under the ephemeral frame cap) and leaves its session and tracks out.
    /// Every `Left` goes signed, and a participant's ends its media keys when it
    /// names the participant id `start` named. Returns the signal, whether it
    /// must go signed, and what it does to the device's call state once it
    /// is sealed ([`OwnEffect`]): nothing changes here, so a seal that fails
    /// changes nothing.
    ///
    /// A `Joined` from a device that is not a v2 participant in the call is
    /// refused ([`super::CALL_STATE_LOST`]): it would go out with no call
    /// key. That is what a core rebuilt mid-call would otherwise send;
    /// neither `end` nor a failed `start` licenses it.
    fn call_media_outgoing(
        &mut self,
        group_id: &[u8],
        signal: &CallSignal,
        signed: bool,
    ) -> Result<(CallSignal, bool, OwnEffect)> {
        if !self.call_media.is_participant(group_id, &signal.call_id) {
            return match &signal.body {
                CallSignalBody::Joined { .. } => Err(Error::invalid(format!(
                    "{}: this device holds no participant media keys for that call (call_media_start to join it again)",
                    super::CALL_STATE_LOST
                ))),
                // Signed whatever this core remembers, so every participant
                // that bound the sender rotates past it.
                CallSignalBody::Left { .. } => Ok((signal.clone(), true, OwnEffect::Nothing)),
                _ => Ok((signal.clone(), false, OwnEffect::Nothing)),
            };
        }
        match &signal.body {
            CallSignalBody::Joined {
                participant_id,
                leaf_index,
                ..
            } => {
                let Some(outgoing) =
                    self.call_media
                        .outgoing_joined(group_id, &signal.call_id, participant_id)?
                else {
                    return Ok((signal.clone(), false, OwnEffect::Nothing));
                };
                Ok((
                    CallSignal {
                        body: CallSignalBody::Joined {
                            participant_id: participant_id.clone(),
                            session_id: String::new(),
                            track_names: Vec::new(),
                            leaf_index: *leaf_index,
                            media_key: outgoing.public_key.to_vec(),
                            started_at_ms: outgoing.mark.started_at_ms,
                            media_key_pq: if signed {
                                outgoing.pq_public_key
                            } else {
                                Vec::new()
                            },
                            participation: Some(outgoing.mark.participation),
                        },
                        ..signal.clone()
                    },
                    false,
                    OwnEffect::Nothing,
                ))
            }
            CallSignalBody::Left { participant_id } => {
                let ends =
                    self.call_media
                        .own_left_ends_media(group_id, &signal.call_id, participant_id);
                Ok((signal.clone(), true, OwnEffect::ends_if(ends)))
            }
            _ => Ok((signal.clone(), false, OwnEffect::Nothing)),
        }
    }

    /// [`Client::seal_call_signal_on_mls_lane`] for a signal in its JSON form.
    pub fn seal_call_signal_on_mls_lane_json(
        &mut self,
        group_id: &[u8],
        signal_json: &str,
    ) -> Result<Vec<u8>> {
        let signal = super::signal_from_json(signal_json)?;
        self.seal_call_signal_on_mls_lane(group_id, &signal)
    }

    /// [`Client::seal_call_signal`] for a signal in its JSON form.
    pub fn seal_call_signal_json(&mut self, group_id: &[u8], signal_json: &str) -> Result<Vec<u8>> {
        let signal = super::signal_from_json(signal_json)?;
        self.seal_call_signal(group_id, &signal)
    }

    /// [`Client::open_call_signal`], answered as [`OpenedCallSignal::to_json`].
    pub fn open_call_signal_json(&mut self, group_id: &[u8], inner: &[u8]) -> Result<String> {
        self.open_call_signal(group_id, inner)?.to_json()
    }
}

impl CallKeys {
    /// The packed form the C and wasm doors hand back:
    /// `epoch u64be ‖ key_index u8 ‖ call_root[32] ‖ count u32be ‖
    /// (leaf_index u32be ‖ key[16])*`.
    ///
    /// Sized before the first write, so no reallocation leaves a key behind.
    /// The bytes are the caller's to wipe: the C door hands them out in a
    /// buffer `peachy_mls_buffer_free` wipes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 1 + CALL_ROOT_BYTES + 4 + self.senders.len() * 20);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.push(self.key_index);
        out.extend_from_slice(&self.call_root[..]);
        let count = u32::try_from(self.senders.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for sender in &self.senders {
            out.extend_from_slice(&sender.leaf_index.to_be_bytes());
            out.extend_from_slice(&sender.key[..]);
        }
        out
    }
}

impl OpenedCallSignal {
    /// `{"lane":"mls"|"live","sender":{"actorId","deviceId"}|null,"senderLeaf",
    /// "urgent":bool,"signal":{…},"send":[hex…],"media":{"senderLeaf",
    /// "generation","sessionId","trackNames","bound"}|null,"unboundLeaf",
    /// "applyAfterMs":n|null,"applied":bool}`, the signal in the fixture's
    /// JSON form.
    pub fn to_json(&self) -> Result<String> {
        let media = self.media.as_ref().map(|grant| {
            serde_json::json!({
                "senderLeaf": grant.sender_leaf,
                "generation": grant.generation,
                "sessionId": grant.session_id,
                "trackNames": grant.track_names,
                "bound": grant.bound,
            })
        });
        let send: Vec<String> = self.send.iter().map(|bytes| super::to_hex(bytes)).collect();
        let signal = serde_json::to_value(super::CallSignalJson::from(&self.signal))
            .map_err(|err| Error::invalid(format!("could not write the call signal: {err}")))?;
        let sender = self.sender.as_ref().map(|identity| {
            serde_json::json!({ "actorId": identity.actor_id, "deviceId": identity.device_id })
        });
        Ok(serde_json::json!({
            "lane": self.lane.name(),
            "sender": sender,
            "senderLeaf": self.sender_leaf,
            "urgent": self.signal.body.is_urgent(),
            "signal": signal,
            "send": send,
            "media": media,
            "unboundLeaf": self.unbound_leaf,
            "applyAfterMs": self.apply_after_ms,
            "applied": self.applied,
        })
        .to_string())
    }
}

/// Whether a signal (JSON form) is sent `urgent` through `SendSealed`:
/// `Offer`, `Answer` and `Hangup` wake a device; nothing else does.
pub fn call_signal_is_urgent_json(signal_json: &str) -> Result<bool> {
    Ok(super::signal_from_json(signal_json)?.body.is_urgent())
}
