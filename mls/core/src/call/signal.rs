// SPDX-License-Identifier: MIT
//! The call signaling codec (docs/calls.md §Signaling).
//!
//! A call signal is a small protobuf of our own, written and read here by
//! hand so the four clients share one implementation and no generated code.
//! It never travels in the clear: it is the plaintext of an MLS application
//! message or of an exporter-keyed live frame ([`super::frame`]), inside an
//! [`ENVELOPE_KIND_CALL`](crate::envelope::ENVELOPE_KIND_CALL) envelope.
//!
//! ```proto
//! message CallSignal {
//!   uint32 version = 1;            // CALL_SIGNAL_VERSION; 0 or absent is not a call signal
//!   bytes  call_id = 2;            // 16 random bytes, chosen by the caller
//!   oneof body {
//!     Offer      offer       = 3;  // MLS lane, urgent
//!     Answer     answer      = 4;  // MLS lane, urgent
//!     Hangup     hangup      = 5;  // MLS lane, urgent
//!     Joined     joined      = 6;  // a participant's first per epoch on the MLS lane; heartbeats live
//!     Left       left        = 7;  // MLS lane, signed
//!     RaiseHand  raise_hand  = 8;  // in-call control: signed, on the MLS lane
//!     React      react       = 9;  // in-call control: signed, on the MLS lane
//!     RemoteMute remote_mute = 10; // in-call control: signed, on the MLS lane
//!     Remove     remove      = 11; // MLS lane: an admin's act, so its sender must be authenticated
//!     MediaState media       = 12; // in-call control: signed, on the MLS lane
//!     Direct     direct      = 13; // MLS lane: a direct 1:1 call's SDP (docs/calls.md §Direct 1:1 calls)
//!     MediaKey   media_key   = 14; // MLS lane: a participant's media secret, granted to participants only
//!   }
//! }
//! enum CallMedia    { AUDIO = 0; VIDEO = 1; }
//! enum HangupReason { NORMAL = 0; DECLINED = 1; BUSY = 2; ACCEPTED_ELSEWHERE = 3;
//!                     DECLINED_ELSEWHERE = 4; BUSY_ELSEWHERE = 5; NEED_PERMISSION = 6; }
//! message Offer      { CallMedia media = 1; bool ring = 2; int64 created_at_ms = 3; }
//! message Answer     { }
//! message Hangup     { HangupReason reason = 1; }
//! message Joined     { string participant_id = 1; string session_id = 2;
//!                      repeated string track_names = 3; uint32 leaf_index = 4;
//!                      bytes media_key = 5;    // v2: the participant's X25519 call public key (32)
//!                      uint64 started_at_ms = 6;    // v2: when its participation started
//!                      bytes media_key_pq = 7;      // v2: its X-Wing call public key (1216), signed Joined only
//!                      bytes participation = 8; }   // v2: id (16) ‖ u64be counter: which participation
//! message Left       { string participant_id = 1; }
//! message RaiseHand  { bool up = 1; }
//! message React      { string emoji = 1; }
//! message RemoteMute { string target = 1; }  // a participant id
//! message Remove     { string target = 1; }  // a participant id
//! message MediaState { bool audio_on = 1; bool video_on = 2; bool presenting = 3; }
//! message Direct     { uint32 to_leaf = 1; string sdp = 2; bool offer = 3; }
//! message MediaKey   { uint32 generation = 1; bool rotated = 2; repeated MediaGrant grants = 3;
//!                      uint64 started_at_ms = 4;    // the granting participation's start
//!                      repeated MediaGrant pq_grants = 5;    // grants sealed to an X-Wing call key
//!                      bytes participation = 6; }   // the granting participation, as in its Joined
//! message MediaGrant { uint32 to_leaf = 1; bytes enc = 2; bytes ciphertext = 3; }
//! ```
//!
//! The lane notes say where a signal travels, not what this codec checks:
//! [`CallSignalBody::is_mls_lane`] lists the bodies that may only go on the
//! MLS lane, and [`super::frame`] says when a `Joined` goes signed.
//!
//! ## Tolerance, which is the point of protobuf here
//!
//! - **Unknown fields are skipped**, at every level, whatever their wire type
//!   (varint, fixed64, length-delimited, fixed32). A newer build may add a
//!   field to any message and an older one reads the rest.
//! - **An unknown message type is not an error**: a signal whose body is a
//!   field this build does not know decodes as [`CallSignalBody::Unknown`],
//!   which every client ignores. A newer build can add an in-call message
//!   without breaking an older one's call.
//! - **An unknown enum value reads as the safe default**: an unknown media as
//!   audio, an unknown hangup reason as `normal`.
//! - **The version is carried, not gated.** A version above 1 still decodes;
//!   the number is there so a future incompatible change has somewhere to say
//!   so. Version 0 (absent) is refused — that is how a byte string that is not
//!   a call signal at all is told apart.
//!
//! What IS refused: a malformed varint or length, a known field with the
//! wrong wire type, a call id that is not 16 bytes, a string that is not
//! UTF-8, a group wire type (deprecated in proto3), a `Direct` with an empty
//! SDP, a `Joined` media key that is neither empty nor 32 bytes, a post-quantum
//! media key that is neither empty nor 1216 bytes or that comes without the
//! X25519 one, a grant in `grants` whose `enc` is not 32 bytes or one in
//! `pq_grants` whose `enc` is not 1120, a grant whose ciphertext is empty,
//! and anything past the
//! size bounds below (an encoded signal of [`MAX_CALL_SIGNAL_BYTES`], 16 384
//! bytes; an SDP of [`MAX_CALL_SDP_BYTES`], 15 360; an id string of 256; a
//! reaction of 64; 32 track names; [`MAX_CALL_MEDIA_GRANTS`] grants).
//!
//! ## Encoding is canonical
//!
//! Fields in number order; `version` and `call_id` always written; inside a
//! body, proto3 defaults (false, 0, "") omitted. So one signal has one byte
//! string, which is what lets the fixture pin bytes.

use serde::{Deserialize, Serialize};

use super::{from_hex, to_hex};
use crate::error::{Error, Result};

/// The version this build writes.
pub const CALL_SIGNAL_VERSION: u32 = 1;
/// A call id: 128 random bits chosen by the caller. Never the group id.
pub const CALL_ID_BYTES: usize = 16;
/// The largest encoded signal this codec writes or reads.
pub const MAX_CALL_SIGNAL_BYTES: usize = 16 * 1024;
/// The longest SDP a `Direct` carries: one complete, non-trickled session
/// description (three m-lines and their candidates).
pub const MAX_CALL_SDP_BYTES: usize = 15 * 1024;
/// The latest `created_at_ms` an Offer may carry: 2^53 - 1, the largest
/// integer every client's number type holds exactly (a JavaScript number, a
/// Swift `Double`). A stamp outside `0..=MAX_CALL_CREATED_AT_MS` is refused,
/// so no client's age arithmetic can overflow on a member's chosen value.
pub const MAX_CALL_CREATED_AT_MS: i64 = (1 << 53) - 1;
/// The longest id string (participant, session, target, track name).
const MAX_ID_BYTES: usize = 256;
/// A participation's mark on the wire: its random id, then its counter.
pub const CALL_PARTICIPATION_BYTES: usize = 24;

/// Which of one device's participations in calls a `Joined` or `MediaKey`
/// speaks for (docs/calls.md §Participant media keys, Binding):
/// `id`, 16 random bytes the core draws at each `start` (and each shared
/// declaration), and `seq`, a counter the device's core keeps in its store
/// and raises by one for each, so a later participation of a device always
/// counts higher, whatever its clock says and across a restart that lost
/// the call's state. On the wire `id ‖ u64be(seq)`, 24 bytes; `seq` is at
/// least 1 and at most 2^53 − 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Participation {
    pub id: [u8; 16],
    pub seq: u64,
}

impl Participation {
    /// The 24 wire bytes.
    pub fn to_bytes(&self) -> [u8; CALL_PARTICIPATION_BYTES] {
        let mut out = [0u8; CALL_PARTICIPATION_BYTES];
        out[..16].copy_from_slice(&self.id);
        out[16..].copy_from_slice(&self.seq.to_be_bytes());
        out
    }

    /// Read the wire bytes: exactly 24, a counter in `1..=2^53−1`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw: [u8; CALL_PARTICIPATION_BYTES] = bytes.try_into().map_err(|_| {
            Error::invalid(format!(
                "a call participation is {CALL_PARTICIPATION_BYTES} bytes, not {}",
                bytes.len()
            ))
        })?;
        let mut id = [0u8; 16];
        id.copy_from_slice(&raw[..16]);
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&raw[16..]);
        let participation = Self {
            id,
            seq: u64::from_be_bytes(seq),
        };
        participation.check()?;
        Ok(participation)
    }

    fn check(&self) -> Result<()> {
        if self.seq == 0 || self.seq > MAX_CALL_CREATED_AT_MS as u64 {
            return Err(Error::invalid(
                "a call participation's counter is outside 1..=2^53-1",
            ));
        }
        Ok(())
    }
}

fn participation_hex(participation: &Option<Participation>) -> String {
    participation.map_or_else(String::new, |p| to_hex(&p.to_bytes()))
}

fn participation_from_hex(hex: &str) -> Result<Option<Participation>> {
    if hex.is_empty() {
        return Ok(None);
    }
    Participation::from_bytes(&from_hex(hex, "participationHex")?).map(Some)
}
/// The longest reaction.
const MAX_EMOJI_BYTES: usize = 64;
/// The most track names one `Joined` lists.
pub(crate) const MAX_TRACKS: usize = 32;
/// The most grants one `MediaKey` carries. A participant granting more seals
/// several `MediaKey` signals ([`crate::Client::call_media_share`]).
pub const MAX_CALL_MEDIA_GRANTS: usize = 24;
/// A participant's call public key: an X25519 HPKE public key, and the length
/// of a classical grant's `enc`.
pub const CALL_MEDIA_PUBLIC_KEY_BYTES: usize = 32;
/// A participant's post-quantum call public key: an X-Wing (ML-KEM-768 +
/// X25519) HPKE public key, in a signed `Joined`'s `media_key_pq`.
pub const CALL_MEDIA_PQ_PUBLIC_KEY_BYTES: usize = 1216;
/// A post-quantum grant's `enc`: an X-Wing encapsulation. Such a grant goes
/// in a `MediaKey`'s `pq_grants` (field 5), which a build that predates it
/// skips: in `grants` (field 3) it would make that build refuse the signal.
pub const CALL_MEDIA_PQ_ENC_BYTES: usize = 1120;

/// Audio or video.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallMedia {
    Audio,
    Video,
}

impl CallMedia {
    fn code(self) -> u64 {
        match self {
            CallMedia::Audio => 0,
            CallMedia::Video => 1,
        }
    }

    fn from_code(code: u64) -> Self {
        match code {
            1 => CallMedia::Video,
            _ => CallMedia::Audio,
        }
    }
}

/// Why a call, or a ring, ended. The `*_elsewhere` reasons go to the user's
/// OWN other devices so they stop ringing; `need_permission` answers a caller
/// the callee has not accepted a message request from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HangupReason {
    Normal,
    Declined,
    Busy,
    AcceptedElsewhere,
    DeclinedElsewhere,
    BusyElsewhere,
    NeedPermission,
}

impl HangupReason {
    /// The wire number.
    pub fn code(self) -> u64 {
        match self {
            HangupReason::Normal => 0,
            HangupReason::Declined => 1,
            HangupReason::Busy => 2,
            HangupReason::AcceptedElsewhere => 3,
            HangupReason::DeclinedElsewhere => 4,
            HangupReason::BusyElsewhere => 5,
            HangupReason::NeedPermission => 6,
        }
    }

    fn from_code(code: u64) -> Self {
        match code {
            1 => HangupReason::Declined,
            2 => HangupReason::Busy,
            3 => HangupReason::AcceptedElsewhere,
            4 => HangupReason::DeclinedElsewhere,
            5 => HangupReason::BusyElsewhere,
            6 => HangupReason::NeedPermission,
            _ => HangupReason::Normal,
        }
    }
}

/// What a signal says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallSignalBody {
    /// Start a call. `ring = false` is a non-ringing group-call notice
    /// (and what a group above [`super::CALL_RING_CAP`] gets).
    Offer {
        media: CallMedia,
        ring: bool,
        created_at_ms: i64,
    },
    /// This device answered.
    Answer,
    /// This device hung up, declined, is busy, or (to its own account's other
    /// devices) answered, declined or was busy elsewhere.
    Hangup {
        reason: HangupReason,
    },
    /// This device is in the call as `participant_id`, publishing these
    /// media-server tracks on `session_id`, and encrypting with the sender key
    /// of `leaf_index`. Sent on joining and every 10 s as a heartbeat.
    ///
    /// `media_key` is the participant's X25519 call public key
    /// ([`CALL_MEDIA_PUBLIC_KEY_BYTES`]): a receiver requires it and tells
    /// the participation's key pair by it, and seals no grant to it.
    /// `session_id` and `track_names` are empty: they travel only inside a
    /// [`MediaGrant`], to participants (docs/calls.md §Participant
    /// media keys).
    ///
    /// `started_at_ms` is the sender's wall clock when its core began this
    /// participation (`start`), filled in by the core. It orders nothing.
    ///
    /// `media_key_pq` is the participant's X-Wing call public key
    /// ([`CALL_MEDIA_PQ_PUBLIC_KEY_BYTES`]), in a signed `Joined` only, and
    /// never without `media_key`: a participant is granted only under it,
    /// post-quantum, and a signed `Joined` without one binds nothing.
    ///
    /// `participation` names the participation by its random id and the
    /// device's counter ([`Participation`]), filled in by the core. A
    /// receiver refuses a signed `Joined` without it, and one from an EARLIER
    /// participation of the device it has bound at that leaf, so a `Joined`
    /// the server held back cannot re-bind the leaf to a call key that died
    /// with the participation.
    Joined {
        participant_id: String,
        session_id: String,
        track_names: Vec<String>,
        leaf_index: u32,
        media_key: Vec<u8>,
        started_at_ms: u64,
        media_key_pq: Vec<u8>,
        participation: Option<Participation>,
    },
    /// This participant left.
    Left {
        participant_id: String,
    },
    RaiseHand {
        up: bool,
    },
    React {
        emoji: String,
    },
    /// Ask `target` to mute.
    RemoteMute {
        target: String,
    },
    /// Remove `target` from the call (group admins).
    Remove {
        target: String,
    },
    /// This participant's own media state.
    Media {
        audio_on: bool,
        video_on: bool,
        presenting: bool,
    },
    /// A direct 1:1 call's session description, for the device at leaf
    /// `to_leaf` only (docs/calls.md §Direct 1:1 calls). `offer` is true
    /// for the answering device's SDP offer, false for the caller's SDP
    /// answer. Signed on the MLS lane: the DTLS fingerprints inside it are
    /// what authenticate the call's DTLS-SRTP end to end.
    Direct {
        to_leaf: u32,
        sdp: String,
        offer: bool,
    },
    /// A participant's media secret at `generation`, granted to other
    /// participants only, each grant sealed to one participant's call public
    /// key (docs/calls.md §Participant media keys). `rotated` is true
    /// for a fresh secret, false for one advanced from the sender's previous
    /// generation, which the participants holding that one advance
    /// themselves. Members see the generation and who is granted, never a
    /// secret. `started_at_ms` and `participation` are the granting
    /// participation's, as in its `Joined`: a grant counts only under the
    /// participation that sent it, and a signed `MediaKey` without the mark
    /// is refused.
    MediaKey {
        generation: u32,
        rotated: bool,
        grants: Vec<MediaGrant>,
        started_at_ms: u64,
        participation: Option<Participation>,
    },
    /// A message type this build does not know. Ignore it.
    Unknown,
}

/// One participant's sealed copy of a [`CallSignalBody::MediaKey`] secret:
/// HPKE (`enc`, `ciphertext`) to `to_leaf`'s call public key. The length of
/// `enc` says which key: [`CALL_MEDIA_PUBLIC_KEY_BYTES`] for the X25519 one
/// (encoded in `grants`), [`CALL_MEDIA_PQ_ENC_BYTES`] for the X-Wing one
/// (encoded in `pq_grants`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaGrant {
    pub to_leaf: u32,
    pub enc: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl CallSignalBody {
    /// Whether this body may travel ONLY on the MLS lane (sender-authenticated,
    /// through the mailbox): [`crate::Client::seal_call_signal`] puts it there,
    /// and a live frame carrying it is refused. That is everything but
    /// `Joined`, `Left` and a body this build does not know (which the live
    /// lane refuses too, as it does a `Left`); a `Joined` or a `Left` may
    /// also go signed, through
    /// [`crate::Client::seal_call_signal_on_mls_lane`].
    pub fn is_mls_lane(&self) -> bool {
        matches!(
            self,
            CallSignalBody::Offer { .. }
                | CallSignalBody::Answer
                | CallSignalBody::Hangup { .. }
                | CallSignalBody::Remove { .. }
                | CallSignalBody::Direct { .. }
                | CallSignalBody::RaiseHand { .. }
                | CallSignalBody::React { .. }
                | CallSignalBody::RemoteMute { .. }
                | CallSignalBody::Media { .. }
                | CallSignalBody::MediaKey { .. }
        )
    }

    /// Whether the mailbox should mark it urgent: the ring-time messages,
    /// which wake a device exactly as a message does (§Ringing). A `Direct`
    /// is not: it follows the urgent `Offer`, so the device it is meant for
    /// is already awake. A ringing callee sends its `Direct` before its person
    /// answers (docs/calls.md §Direct 1:1 calls), so the two devices
    /// are not yet both in the call. A `MediaKey` is not urgent either: only
    /// devices already in the call act on it.
    pub fn is_urgent(&self) -> bool {
        matches!(
            self,
            CallSignalBody::Offer { .. } | CallSignalBody::Answer | CallSignalBody::Hangup { .. }
        )
    }
}

/// One call signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSignal {
    pub version: u32,
    pub call_id: [u8; CALL_ID_BYTES],
    pub body: CallSignalBody,
}

impl CallSignal {
    /// A signal at this build's version.
    pub fn new(call_id: [u8; CALL_ID_BYTES], body: CallSignalBody) -> Self {
        Self {
            version: CALL_SIGNAL_VERSION,
            call_id,
            body,
        }
    }
}

// ---- Encoding ----------------------------------------------------------------

const WIRE_VARINT: u64 = 0;
const WIRE_FIXED64: u64 = 1;
const WIRE_LEN: u64 = 2;
const WIRE_FIXED32: u64 = 5;

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn put_tag(out: &mut Vec<u8>, field: u64, wire: u64) {
    put_varint(out, (field << 3) | wire);
}

fn put_uint(out: &mut Vec<u8>, field: u64, value: u64) {
    if value != 0 {
        put_tag(out, field, WIRE_VARINT);
        put_varint(out, value);
    }
}

fn put_bool(out: &mut Vec<u8>, field: u64, value: bool) {
    put_uint(out, field, u64::from(value));
}

fn put_bytes(out: &mut Vec<u8>, field: u64, value: &[u8]) {
    put_tag(out, field, WIRE_LEN);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn put_string(out: &mut Vec<u8>, field: u64, value: &str) {
    if !value.is_empty() {
        put_bytes(out, field, value.as_bytes());
    }
}

fn check_len(value: &str, max: usize, what: &str) -> Result<()> {
    if value.len() > max {
        return Err(Error::invalid(format!(
            "a call signal's {what} is at most {max} bytes"
        )));
    }
    Ok(())
}

/// Encode `signal`, canonically. Refuses [`CallSignalBody::Unknown`] (there is
/// nothing to say) and anything past the size bounds.
pub fn encode_call_signal(signal: &CallSignal) -> Result<Vec<u8>> {
    if signal.version == 0 {
        return Err(Error::invalid("a call signal's version is at least 1"));
    }
    let mut body = Vec::new();
    let field = match &signal.body {
        CallSignalBody::Offer {
            media,
            ring,
            created_at_ms,
        } => {
            check_created_at(*created_at_ms)?;
            put_uint(&mut body, 1, media.code());
            put_bool(&mut body, 2, *ring);
            // int64: a negative value is its two's complement as a u64, as
            // protobuf writes it.
            put_uint(&mut body, 3, *created_at_ms as u64);
            3
        }
        CallSignalBody::Answer => 4,
        CallSignalBody::Hangup { reason } => {
            put_uint(&mut body, 1, reason.code());
            5
        }
        CallSignalBody::Joined {
            participant_id,
            session_id,
            track_names,
            leaf_index,
            media_key,
            started_at_ms,
            media_key_pq,
            participation,
        } => {
            check_started_at(*started_at_ms)?;
            if let Some(participation) = participation {
                participation.check()?;
            }
            check_len(participant_id, MAX_ID_BYTES, "participant id")?;
            check_len(session_id, MAX_ID_BYTES, "session id")?;
            if track_names.len() > MAX_TRACKS {
                return Err(Error::invalid(format!(
                    "a call signal lists at most {MAX_TRACKS} tracks"
                )));
            }
            check_media_key(media_key, media_key_pq)?;
            put_string(&mut body, 1, participant_id);
            put_string(&mut body, 2, session_id);
            for track in track_names {
                check_len(track, MAX_ID_BYTES, "track name")?;
                // Repeated: every element written, an empty one included.
                put_bytes(&mut body, 3, track.as_bytes());
            }
            put_uint(&mut body, 4, u64::from(*leaf_index));
            if !media_key.is_empty() {
                put_bytes(&mut body, 5, media_key);
            }
            put_uint(&mut body, 6, *started_at_ms);
            if !media_key_pq.is_empty() {
                put_bytes(&mut body, 7, media_key_pq);
            }
            if let Some(participation) = participation {
                put_bytes(&mut body, 8, &participation.to_bytes());
            }
            6
        }
        CallSignalBody::Left { participant_id } => {
            check_len(participant_id, MAX_ID_BYTES, "participant id")?;
            put_string(&mut body, 1, participant_id);
            7
        }
        CallSignalBody::RaiseHand { up } => {
            put_bool(&mut body, 1, *up);
            8
        }
        CallSignalBody::React { emoji } => {
            check_len(emoji, MAX_EMOJI_BYTES, "reaction")?;
            put_string(&mut body, 1, emoji);
            9
        }
        CallSignalBody::RemoteMute { target } => {
            check_len(target, MAX_ID_BYTES, "target")?;
            put_string(&mut body, 1, target);
            10
        }
        CallSignalBody::Remove { target } => {
            check_len(target, MAX_ID_BYTES, "target")?;
            put_string(&mut body, 1, target);
            11
        }
        CallSignalBody::Media {
            audio_on,
            video_on,
            presenting,
        } => {
            put_bool(&mut body, 1, *audio_on);
            put_bool(&mut body, 2, *video_on);
            put_bool(&mut body, 3, *presenting);
            12
        }
        CallSignalBody::Direct {
            to_leaf,
            sdp,
            offer,
        } => {
            if sdp.is_empty() {
                return Err(Error::invalid("a direct call signal carries an SDP"));
            }
            check_len(sdp, MAX_CALL_SDP_BYTES, "SDP")?;
            put_uint(&mut body, 1, u64::from(*to_leaf));
            put_string(&mut body, 2, sdp);
            put_bool(&mut body, 3, *offer);
            13
        }
        CallSignalBody::MediaKey {
            generation,
            rotated,
            grants,
            started_at_ms,
            participation,
        } => {
            check_started_at(*started_at_ms)?;
            if let Some(participation) = participation {
                participation.check()?;
            }
            check_grant_count(grants.len())?;
            put_uint(&mut body, 1, u64::from(*generation));
            put_bool(&mut body, 2, *rotated);
            // Classical grants in field 3, post-quantum ones in field 5,
            // each list in the order given: fields stay in number order.
            let encode_grant = |grant: &MediaGrant| -> Result<Vec<u8>> {
                check_grant_ciphertext(&grant.ciphertext)?;
                let mut inner = Vec::with_capacity(grant.enc.len() + grant.ciphertext.len() + 12);
                put_uint(&mut inner, 1, u64::from(grant.to_leaf));
                put_bytes(&mut inner, 2, &grant.enc);
                put_bytes(&mut inner, 3, &grant.ciphertext);
                Ok(inner)
            };
            let mut pq = Vec::new();
            for grant in grants {
                match grant.enc.len() {
                    CALL_MEDIA_PUBLIC_KEY_BYTES => put_bytes(&mut body, 3, &encode_grant(grant)?),
                    CALL_MEDIA_PQ_ENC_BYTES => pq.push(encode_grant(grant)?),
                    other => {
                        return Err(Error::invalid(format!(
                            "a media grant's enc is {CALL_MEDIA_PUBLIC_KEY_BYTES} or {CALL_MEDIA_PQ_ENC_BYTES} bytes, not {other}"
                        )))
                    }
                }
            }
            put_uint(&mut body, 4, *started_at_ms);
            for inner in &pq {
                put_bytes(&mut body, 5, inner);
            }
            if let Some(participation) = participation {
                put_bytes(&mut body, 6, &participation.to_bytes());
            }
            14
        }
        CallSignalBody::Unknown => {
            return Err(Error::invalid(
                "an unknown call signal cannot be encoded: there is nothing to say",
            ))
        }
    };
    let mut out = Vec::with_capacity(body.len() + 32);
    put_uint(&mut out, 1, u64::from(signal.version));
    put_bytes(&mut out, 2, &signal.call_id);
    put_bytes(&mut out, field, &body);
    if out.len() > MAX_CALL_SIGNAL_BYTES {
        return Err(Error::invalid(format!(
            "a call signal is at most {MAX_CALL_SIGNAL_BYTES} bytes"
        )));
    }
    Ok(out)
}

// ---- Decoding ----------------------------------------------------------------

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

enum Value<'a> {
    Varint(u64),
    Len(&'a [u8]),
    Fixed,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value: u64 = 0;
        for shift in (0..64).step_by(7) {
            let byte = *self
                .bytes
                .get(self.at)
                .ok_or_else(|| Error::invalid("a call signal ends inside a varint"))?;
            self.at += 1;
            let low = u64::from(byte & 0x7f);
            if shift == 63 && low > 1 {
                return Err(Error::invalid("a call signal's varint overflows 64 bits"));
            }
            value |= low << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Error::invalid(
            "a call signal's varint is longer than 10 bytes",
        ))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| Error::invalid("a call signal's field runs past its end"))?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| Error::invalid("a call signal's field runs past its end"))?;
        self.at = end;
        Ok(slice)
    }

    /// The next field: its number and value.
    fn field(&mut self) -> Result<(u64, Value<'a>)> {
        let tag = self.varint()?;
        let number = tag >> 3;
        if number == 0 {
            return Err(Error::invalid("a call signal has a field numbered 0"));
        }
        let value = match tag & 0x7 {
            WIRE_VARINT => Value::Varint(self.varint()?),
            WIRE_FIXED64 => {
                self.take(8)?;
                Value::Fixed
            }
            WIRE_LEN => {
                let len = usize::try_from(self.varint()?)
                    .map_err(|_| Error::invalid("a call signal's length overflows"))?;
                Value::Len(self.take(len)?)
            }
            WIRE_FIXED32 => {
                self.take(4)?;
                Value::Fixed
            }
            other => {
                return Err(Error::invalid(format!(
                    "a call signal uses wire type {other}, which proto3 does not"
                )))
            }
        };
        Ok((number, value))
    }
}

/// The top-level field of an encoded `CallSignal` that carries a live
/// frame's signature (docs/calls.md §The live lane's signature):
/// 64 bytes, written last. A number no body will ever take, so a build that
/// does not know it skips it as any unknown top-level field.
pub const CALL_LIVE_SIGNATURE_FIELD: u64 = 64;
/// An Ed25519 signature.
pub const CALL_LIVE_SIGNATURE_BYTES: usize = 64;

/// Append a live frame's signature to an encoded signal, as its last field.
pub fn append_live_signature(encoded: &mut Vec<u8>, signature: &[u8; CALL_LIVE_SIGNATURE_BYTES]) {
    put_varint(encoded, (CALL_LIVE_SIGNATURE_FIELD << 3) | WIRE_LEN);
    put_varint(encoded, CALL_LIVE_SIGNATURE_BYTES as u64);
    encoded.extend_from_slice(signature);
}

/// An encoded signal's bytes before its live signature, and the signature,
/// or the whole of it and `None` when it carries none. A signature field
/// that is not length-delimited, not 64 bytes, not the last field, or there
/// twice is refused, so one signal has one reading.
pub fn split_live_signature(
    encoded: &[u8],
) -> Result<(&[u8], Option<[u8; CALL_LIVE_SIGNATURE_BYTES]>)> {
    let mut reader = Reader::new(encoded);
    let mut found: Option<(usize, [u8; CALL_LIVE_SIGNATURE_BYTES])> = None;
    while !reader.done() {
        let start = reader.at;
        let (number, value) = reader.field()?;
        if found.is_some() {
            return Err(Error::invalid(
                "a call signal's live signature is not its last field",
            ));
        }
        if number == CALL_LIVE_SIGNATURE_FIELD {
            let raw = want_bytes(value, "live signature")?;
            let signature: [u8; CALL_LIVE_SIGNATURE_BYTES] = raw.try_into().map_err(|_| {
                Error::invalid(format!(
                    "a call signal's live signature is {CALL_LIVE_SIGNATURE_BYTES} bytes, not {}",
                    raw.len()
                ))
            })?;
            found = Some((start, signature));
        }
    }
    Ok(match found {
        Some((start, signature)) => (encoded.get(..start).unwrap_or_default(), Some(signature)),
        None => (encoded, None),
    })
}

fn want_varint(value: Value<'_>, what: &str) -> Result<u64> {
    match value {
        Value::Varint(v) => Ok(v),
        _ => Err(Error::invalid(format!(
            "a call signal's {what} is not a varint"
        ))),
    }
}

fn want_bytes<'a>(value: Value<'a>, what: &str) -> Result<&'a [u8]> {
    match value {
        Value::Len(v) => Ok(v),
        _ => Err(Error::invalid(format!(
            "a call signal's {what} is not length-delimited"
        ))),
    }
}

fn want_string(value: Value<'_>, what: &str, max: usize) -> Result<String> {
    let bytes = want_bytes(value, what)?;
    if bytes.len() > max {
        return Err(Error::invalid(format!(
            "a call signal's {what} is at most {max} bytes"
        )));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| Error::invalid(format!("a call signal's {what} is not UTF-8")))
}

fn want_u32(value: Value<'_>, what: &str) -> Result<u32> {
    u32::try_from(want_varint(value, what)?)
        .map_err(|_| Error::invalid(format!("a call signal's {what} overflows 32 bits")))
}

/// Read every field of a body with `on`, skipping the ones it does not claim.
fn each_field<'a>(
    bytes: &'a [u8],
    mut on: impl FnMut(u64, Value<'a>) -> Result<bool>,
) -> Result<()> {
    let mut reader = Reader::new(bytes);
    while !reader.done() {
        let (number, value) = reader.field()?;
        // `on` returns whether it knew the field; an unknown one is skipped,
        // which `field()` has already done by reading past it.
        let _known = on(number, value)?;
    }
    Ok(())
}

fn check_media_key(media_key: &[u8], media_key_pq: &[u8]) -> Result<()> {
    if !media_key.is_empty() && media_key.len() != CALL_MEDIA_PUBLIC_KEY_BYTES {
        return Err(Error::invalid(format!(
            "a Joined's media key is {CALL_MEDIA_PUBLIC_KEY_BYTES} bytes or absent, not {}",
            media_key.len()
        )));
    }
    if !media_key_pq.is_empty() && media_key_pq.len() != CALL_MEDIA_PQ_PUBLIC_KEY_BYTES {
        return Err(Error::invalid(format!(
            "a Joined's post-quantum media key is {CALL_MEDIA_PQ_PUBLIC_KEY_BYTES} bytes or absent, not {}",
            media_key_pq.len()
        )));
    }
    if !media_key_pq.is_empty() && media_key.is_empty() {
        return Err(Error::invalid(
            "a Joined's post-quantum media key comes with its X25519 one",
        ));
    }
    Ok(())
}

fn check_grant_count(count: usize) -> Result<()> {
    if count > MAX_CALL_MEDIA_GRANTS {
        return Err(Error::invalid(format!(
            "a media key carries at most {MAX_CALL_MEDIA_GRANTS} grants"
        )));
    }
    Ok(())
}

fn check_grant_ciphertext(ciphertext: &[u8]) -> Result<()> {
    if ciphertext.is_empty() {
        return Err(Error::invalid("a media grant carries a ciphertext"));
    }
    Ok(())
}

/// A grant whose `enc` is `enc_bytes` long: [`CALL_MEDIA_PUBLIC_KEY_BYTES`]
/// in `grants`, [`CALL_MEDIA_PQ_ENC_BYTES`] in `pq_grants`.
fn check_grant(enc: &[u8], ciphertext: &[u8], enc_bytes: usize) -> Result<()> {
    if enc.len() != enc_bytes {
        return Err(Error::invalid(format!(
            "a media grant's enc is {enc_bytes} bytes, not {}",
            enc.len()
        )));
    }
    check_grant_ciphertext(ciphertext)
}

fn decode_grant(bytes: &[u8], enc_bytes: usize) -> Result<MediaGrant> {
    let (mut to_leaf, mut enc, mut ciphertext) = (0u32, Vec::new(), Vec::new());
    each_field(bytes, |n, v| {
        match n {
            1 => to_leaf = want_u32(v, "grant to_leaf")?,
            2 => enc = want_bytes(v, "grant enc")?.to_vec(),
            3 => ciphertext = want_bytes(v, "grant ciphertext")?.to_vec(),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    check_grant(&enc, &ciphertext, enc_bytes)?;
    Ok(MediaGrant {
        to_leaf,
        enc,
        ciphertext,
    })
}

fn check_created_at(created_at_ms: i64) -> Result<()> {
    if !(0..=MAX_CALL_CREATED_AT_MS).contains(&created_at_ms) {
        return Err(Error::invalid(
            "an offer's created_at_ms is outside the range every client can age",
        ));
    }
    Ok(())
}

/// A participation's start is a wall-clock millisecond every client's number
/// type holds exactly, as an offer's `created_at_ms` is.
fn check_started_at(started_at_ms: u64) -> Result<()> {
    if started_at_ms > MAX_CALL_CREATED_AT_MS as u64 {
        return Err(Error::invalid(
            "a call signal's started_at_ms is outside the range every client holds",
        ));
    }
    Ok(())
}

fn decode_body(field: u64, bytes: &[u8]) -> Result<CallSignalBody> {
    Ok(match field {
        3 => {
            let (mut media, mut ring, mut created_at_ms) = (CallMedia::Audio, false, 0i64);
            each_field(bytes, |n, v| {
                match n {
                    1 => media = CallMedia::from_code(want_varint(v, "media")?),
                    2 => ring = want_varint(v, "ring")? != 0,
                    3 => created_at_ms = want_varint(v, "created_at_ms")? as i64,
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            check_created_at(created_at_ms)?;
            CallSignalBody::Offer {
                media,
                ring,
                created_at_ms,
            }
        }
        4 => {
            each_field(bytes, |_, _| Ok(false))?;
            CallSignalBody::Answer
        }
        5 => {
            let mut reason = HangupReason::Normal;
            each_field(bytes, |n, v| {
                match n {
                    1 => reason = HangupReason::from_code(want_varint(v, "reason")?),
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            CallSignalBody::Hangup { reason }
        }
        6 => {
            let (mut participant_id, mut session_id) = (String::new(), String::new());
            let (mut track_names, mut leaf_index) = (Vec::new(), 0u32);
            let (mut media_key, mut started_at_ms) = (Vec::new(), 0u64);
            let mut media_key_pq = Vec::new();
            let mut participation = None;
            each_field(bytes, |n, v| {
                match n {
                    1 => participant_id = want_string(v, "participant id", MAX_ID_BYTES)?,
                    2 => session_id = want_string(v, "session id", MAX_ID_BYTES)?,
                    3 => {
                        if track_names.len() >= MAX_TRACKS {
                            return Err(Error::invalid(format!(
                                "a call signal lists at most {MAX_TRACKS} tracks"
                            )));
                        }
                        track_names.push(want_string(v, "track name", MAX_ID_BYTES)?);
                    }
                    4 => leaf_index = want_u32(v, "leaf index")?,
                    5 => media_key = want_bytes(v, "media key")?.to_vec(),
                    6 => started_at_ms = want_varint(v, "started_at_ms")?,
                    7 => media_key_pq = want_bytes(v, "post-quantum media key")?.to_vec(),
                    8 => {
                        participation =
                            Some(Participation::from_bytes(want_bytes(v, "participation")?)?)
                    }
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            check_media_key(&media_key, &media_key_pq)?;
            check_started_at(started_at_ms)?;
            CallSignalBody::Joined {
                participant_id,
                session_id,
                track_names,
                leaf_index,
                media_key,
                started_at_ms,
                media_key_pq,
                participation,
            }
        }
        7 | 10 | 11 => {
            let mut id = String::new();
            each_field(bytes, |n, v| {
                match n {
                    1 => id = want_string(v, "participant id", MAX_ID_BYTES)?,
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            match field {
                7 => CallSignalBody::Left { participant_id: id },
                10 => CallSignalBody::RemoteMute { target: id },
                _ => CallSignalBody::Remove { target: id },
            }
        }
        8 => {
            let mut up = false;
            each_field(bytes, |n, v| {
                match n {
                    1 => up = want_varint(v, "up")? != 0,
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            CallSignalBody::RaiseHand { up }
        }
        9 => {
            let mut emoji = String::new();
            each_field(bytes, |n, v| {
                match n {
                    1 => emoji = want_string(v, "reaction", MAX_EMOJI_BYTES)?,
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            CallSignalBody::React { emoji }
        }
        12 => {
            let (mut audio_on, mut video_on, mut presenting) = (false, false, false);
            each_field(bytes, |n, v| {
                match n {
                    1 => audio_on = want_varint(v, "audio_on")? != 0,
                    2 => video_on = want_varint(v, "video_on")? != 0,
                    3 => presenting = want_varint(v, "presenting")? != 0,
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            CallSignalBody::Media {
                audio_on,
                video_on,
                presenting,
            }
        }
        13 => {
            let (mut to_leaf, mut sdp, mut offer) = (0u32, String::new(), false);
            each_field(bytes, |n, v| {
                match n {
                    1 => to_leaf = want_u32(v, "to_leaf")?,
                    2 => sdp = want_string(v, "SDP", MAX_CALL_SDP_BYTES)?,
                    3 => offer = want_varint(v, "offer")? != 0,
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            if sdp.is_empty() {
                return Err(Error::invalid("a direct call signal carries an SDP"));
            }
            CallSignalBody::Direct {
                to_leaf,
                sdp,
                offer,
            }
        }
        14 => {
            let (mut generation, mut rotated, mut grants) = (0u32, false, Vec::new());
            let mut started_at_ms = 0u64;
            let mut participation = None;
            each_field(bytes, |n, v| {
                match n {
                    1 => generation = want_u32(v, "generation")?,
                    2 => rotated = want_varint(v, "rotated")? != 0,
                    3 => {
                        check_grant_count(grants.len() + 1)?;
                        grants.push(decode_grant(
                            want_bytes(v, "grant")?,
                            CALL_MEDIA_PUBLIC_KEY_BYTES,
                        )?);
                    }
                    4 => started_at_ms = want_varint(v, "started_at_ms")?,
                    5 => {
                        check_grant_count(grants.len() + 1)?;
                        grants.push(decode_grant(
                            want_bytes(v, "post-quantum grant")?,
                            CALL_MEDIA_PQ_ENC_BYTES,
                        )?);
                    }
                    6 => {
                        participation =
                            Some(Participation::from_bytes(want_bytes(v, "participation")?)?)
                    }
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            check_started_at(started_at_ms)?;
            CallSignalBody::MediaKey {
                generation,
                rotated,
                grants,
                started_at_ms,
                participation,
            }
        }
        _ => CallSignalBody::Unknown,
    })
}

/// What one media grant carries, sealed to one participant
/// (docs/calls.md §Participant media keys):
///
/// ```proto
/// message MediaGrantPayload { uint32 generation = 1; bytes secret = 2;
///                             string session_id = 3; repeated string track_names = 4; }
/// ```
///
/// The sender's media secret at `generation`, and its media-server session
/// and tracks, which are what let a holder pull its media.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaGrantPayload {
    pub generation: u32,
    pub secret: crate::secret::Secret<[u8; super::CALL_MEDIA_SEED_BYTES]>,
    pub session_id: String,
    pub track_names: Vec<String>,
}

/// Encode a grant's plaintext, canonically.
pub fn encode_media_grant_payload(payload: &MediaGrantPayload) -> Result<Vec<u8>> {
    check_len(&payload.session_id, MAX_ID_BYTES, "session id")?;
    if payload.track_names.len() > MAX_TRACKS {
        return Err(Error::invalid(format!(
            "a call signal lists at most {MAX_TRACKS} tracks"
        )));
    }
    // Every check before the secret is written: an error after it would drop
    // the buffer, secret and all, before the caller could wrap it.
    for track in &payload.track_names {
        check_len(track, MAX_ID_BYTES, "track name")?;
    }
    // Sized for every field up front: the secret goes in first, and a
    // buffer that grew would leave a copy of it behind unwiped.
    let tracks: usize = payload.track_names.iter().map(|t| t.len() + 8).sum();
    let mut out = Vec::with_capacity(64 + payload.session_id.len() + tracks);
    put_uint(&mut out, 1, u64::from(payload.generation));
    put_bytes(&mut out, 2, &payload.secret[..]);
    put_string(&mut out, 3, &payload.session_id);
    for track in &payload.track_names {
        put_bytes(&mut out, 4, track.as_bytes());
    }
    Ok(out)
}

/// Decode a grant's plaintext. Unknown fields are skipped; a secret that is
/// not 32 bytes is refused.
pub fn decode_media_grant_payload(bytes: &[u8]) -> Result<MediaGrantPayload> {
    let (mut generation, mut secret, mut session_id) = (0u32, None, String::new());
    let mut track_names = Vec::new();
    each_field(bytes, |n, v| {
        match n {
            1 => generation = want_u32(v, "generation")?,
            2 => {
                let raw = want_bytes(v, "media secret")?;
                secret = Some(<[u8; super::CALL_MEDIA_SEED_BYTES]>::try_from(raw).map_err(
                    |_| {
                        Error::invalid(format!(
                            "a media secret is {} bytes, not {}",
                            super::CALL_MEDIA_SEED_BYTES,
                            raw.len()
                        ))
                    },
                )?);
            }
            3 => session_id = want_string(v, "session id", MAX_ID_BYTES)?,
            4 => {
                if track_names.len() >= MAX_TRACKS {
                    return Err(Error::invalid(format!(
                        "a call signal lists at most {MAX_TRACKS} tracks"
                    )));
                }
                track_names.push(want_string(v, "track name", MAX_ID_BYTES)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(MediaGrantPayload {
        generation,
        secret: crate::secret::Secret::new(
            secret.ok_or_else(|| Error::invalid("a media grant carries a secret"))?,
        ),
        session_id,
        track_names,
    })
}

/// Decode a call signal, tolerating what a newer build adds (see the module
/// header for exactly what is tolerated and what is refused).
pub fn decode_call_signal(bytes: &[u8]) -> Result<CallSignal> {
    if bytes.len() > MAX_CALL_SIGNAL_BYTES {
        return Err(Error::invalid(format!(
            "a call signal is at most {MAX_CALL_SIGNAL_BYTES} bytes"
        )));
    }
    let mut version: u32 = 0;
    let mut call_id: Option<[u8; CALL_ID_BYTES]> = None;
    let mut body: Option<(u64, &[u8])> = None;
    let mut reader = Reader::new(bytes);
    while !reader.done() {
        let (number, value) = reader.field()?;
        match number {
            1 => version = want_u32(value, "version")?,
            2 => {
                let raw = want_bytes(value, "call id")?;
                let id: [u8; CALL_ID_BYTES] = raw.try_into().map_err(|_| {
                    Error::invalid(format!(
                        "a call id is {CALL_ID_BYTES} bytes, not {}",
                        raw.len()
                    ))
                })?;
                call_id = Some(id);
            }
            3..=14 => body = Some((number, want_bytes(value, "body")?)),
            // An unknown top-level field: a newer build's addition. If it was
            // a new message type, the body stays unknown below.
            _ => {}
        }
    }
    if version == 0 {
        return Err(Error::invalid(
            "that is not a call signal: it carries no version",
        ));
    }
    let call_id = call_id.ok_or_else(|| Error::invalid("a call signal carries a call id"))?;
    let body = match body {
        Some((field, bytes)) => decode_body(field, bytes)?,
        None => CallSignalBody::Unknown,
    };
    Ok(CallSignal {
        version,
        call_id,
        body,
    })
}

// ---- The JSON form the bindings cross with -------------------------------------

/// A call signal as JSON: what Swift, Kotlin and JavaScript hand the core and
/// get back. `callId` is 32 hex digits; `type` names the body.
///
/// ```json
/// {"version":1,"callId":"00112233445566778899aabbccddeeff","type":"offer",
///  "media":"video","ring":true,"createdAtMs":1789516800000}
/// {"version":1,"callId":"…","type":"hangup","reason":"declined_elsewhere"}
/// {"version":1,"callId":"…","type":"joined","participantId":"p","sessionId":"s",
///  "trackNames":["a","v"],"leafIndex":2}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallSignalJson {
    #[serde(default = "this_version")]
    pub version: u32,
    pub call_id: String,
    #[serde(flatten)]
    pub body: CallSignalBodyJson,
}

fn this_version() -> u32 {
    CALL_SIGNAL_VERSION
}

/// The body of a [`CallSignalJson`], tagged by `type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum CallSignalBodyJson {
    #[serde(rename_all = "camelCase")]
    Offer {
        media: CallMedia,
        #[serde(default)]
        ring: bool,
        #[serde(default)]
        created_at_ms: i64,
    },
    Answer,
    Hangup {
        reason: HangupReason,
    },
    #[serde(rename_all = "camelCase")]
    Joined {
        participant_id: String,
        session_id: String,
        #[serde(default)]
        track_names: Vec<String>,
        leaf_index: u32,
        /// The participant's X25519 call public key, 64 hex digits, in a
        /// signed `Joined`; the core fills it in.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        media_key_hex: String,
        /// When the participation started; the core fills it in on the way
        /// out, whatever a client passes. Absent reads as 0.
        #[serde(default, skip_serializing_if = "is_zero")]
        started_at_ms: u64,
        /// The participant's X-Wing call public key, 2432 hex digits, in a
        /// signed `Joined`; the core fills it in.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        media_key_pq_hex: String,
        /// The participation's id and counter, 48 hex digits; the core fills
        /// it in.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        participation_hex: String,
    },
    #[serde(rename_all = "camelCase")]
    Left {
        participant_id: String,
    },
    RaiseHand {
        up: bool,
    },
    React {
        emoji: String,
    },
    RemoteMute {
        target: String,
    },
    Remove {
        target: String,
    },
    #[serde(rename_all = "camelCase")]
    Media {
        audio_on: bool,
        video_on: bool,
        #[serde(default)]
        presenting: bool,
    },
    #[serde(rename_all = "camelCase")]
    Direct {
        to_leaf: u32,
        sdp: String,
        #[serde(default)]
        offer: bool,
    },
    #[serde(rename_all = "camelCase")]
    MediaKey {
        generation: u32,
        #[serde(default)]
        rotated: bool,
        #[serde(default)]
        grants: Vec<MediaGrantJson>,
        #[serde(default, skip_serializing_if = "is_zero")]
        started_at_ms: u64,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        participation_hex: String,
    },
    Unknown,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// A [`MediaGrant`] as JSON: `{"toLeaf":n,"encHex":"…","ciphertextHex":"…"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaGrantJson {
    pub to_leaf: u32,
    pub enc_hex: String,
    pub ciphertext_hex: String,
}

impl From<&CallSignal> for CallSignalJson {
    fn from(signal: &CallSignal) -> Self {
        let body = match &signal.body {
            CallSignalBody::Offer {
                media,
                ring,
                created_at_ms,
            } => CallSignalBodyJson::Offer {
                media: *media,
                ring: *ring,
                created_at_ms: *created_at_ms,
            },
            CallSignalBody::Answer => CallSignalBodyJson::Answer,
            CallSignalBody::Hangup { reason } => CallSignalBodyJson::Hangup { reason: *reason },
            CallSignalBody::Joined {
                participant_id,
                session_id,
                track_names,
                leaf_index,
                media_key,
                started_at_ms,
                media_key_pq,
                participation,
            } => CallSignalBodyJson::Joined {
                participant_id: participant_id.clone(),
                session_id: session_id.clone(),
                track_names: track_names.clone(),
                leaf_index: *leaf_index,
                media_key_hex: to_hex(media_key),
                started_at_ms: *started_at_ms,
                media_key_pq_hex: to_hex(media_key_pq),
                participation_hex: participation_hex(participation),
            },
            CallSignalBody::Left { participant_id } => CallSignalBodyJson::Left {
                participant_id: participant_id.clone(),
            },
            CallSignalBody::RaiseHand { up } => CallSignalBodyJson::RaiseHand { up: *up },
            CallSignalBody::React { emoji } => CallSignalBodyJson::React {
                emoji: emoji.clone(),
            },
            CallSignalBody::RemoteMute { target } => CallSignalBodyJson::RemoteMute {
                target: target.clone(),
            },
            CallSignalBody::Remove { target } => CallSignalBodyJson::Remove {
                target: target.clone(),
            },
            CallSignalBody::Media {
                audio_on,
                video_on,
                presenting,
            } => CallSignalBodyJson::Media {
                audio_on: *audio_on,
                video_on: *video_on,
                presenting: *presenting,
            },
            CallSignalBody::Direct {
                to_leaf,
                sdp,
                offer,
            } => CallSignalBodyJson::Direct {
                to_leaf: *to_leaf,
                sdp: sdp.clone(),
                offer: *offer,
            },
            CallSignalBody::MediaKey {
                generation,
                rotated,
                grants,
                started_at_ms,
                participation,
            } => CallSignalBodyJson::MediaKey {
                generation: *generation,
                rotated: *rotated,
                started_at_ms: *started_at_ms,
                participation_hex: participation_hex(participation),
                grants: grants
                    .iter()
                    .map(|grant| MediaGrantJson {
                        to_leaf: grant.to_leaf,
                        enc_hex: to_hex(&grant.enc),
                        ciphertext_hex: to_hex(&grant.ciphertext),
                    })
                    .collect(),
            },
            CallSignalBody::Unknown => CallSignalBodyJson::Unknown,
        };
        CallSignalJson {
            version: signal.version,
            call_id: to_hex(&signal.call_id),
            body,
        }
    }
}

impl TryFrom<&CallSignalJson> for CallSignal {
    type Error = Error;

    fn try_from(json: &CallSignalJson) -> Result<Self> {
        let raw = from_hex(&json.call_id, "callId")?;
        let call_id: [u8; CALL_ID_BYTES] = raw.as_slice().try_into().map_err(|_| {
            Error::invalid(format!(
                "a call id is {CALL_ID_BYTES} bytes ({} hex digits), not {}",
                CALL_ID_BYTES * 2,
                raw.len()
            ))
        })?;
        let body = match &json.body {
            CallSignalBodyJson::Offer {
                media,
                ring,
                created_at_ms,
            } => CallSignalBody::Offer {
                media: *media,
                ring: *ring,
                created_at_ms: *created_at_ms,
            },
            CallSignalBodyJson::Answer => CallSignalBody::Answer,
            CallSignalBodyJson::Hangup { reason } => CallSignalBody::Hangup { reason: *reason },
            CallSignalBodyJson::Joined {
                participant_id,
                session_id,
                track_names,
                leaf_index,
                media_key_hex,
                started_at_ms,
                media_key_pq_hex,
                participation_hex,
            } => {
                let participation = participation_from_hex(participation_hex)?;
                let media_key = from_hex(media_key_hex, "mediaKeyHex")?;
                let media_key_pq = from_hex(media_key_pq_hex, "mediaKeyPqHex")?;
                check_media_key(&media_key, &media_key_pq)?;
                check_started_at(*started_at_ms)?;
                CallSignalBody::Joined {
                    participant_id: participant_id.clone(),
                    session_id: session_id.clone(),
                    track_names: track_names.clone(),
                    leaf_index: *leaf_index,
                    media_key,
                    started_at_ms: *started_at_ms,
                    media_key_pq,
                    participation,
                }
            }
            CallSignalBodyJson::Left { participant_id } => CallSignalBody::Left {
                participant_id: participant_id.clone(),
            },
            CallSignalBodyJson::RaiseHand { up } => CallSignalBody::RaiseHand { up: *up },
            CallSignalBodyJson::React { emoji } => CallSignalBody::React {
                emoji: emoji.clone(),
            },
            CallSignalBodyJson::RemoteMute { target } => CallSignalBody::RemoteMute {
                target: target.clone(),
            },
            CallSignalBodyJson::Remove { target } => CallSignalBody::Remove {
                target: target.clone(),
            },
            CallSignalBodyJson::Media {
                audio_on,
                video_on,
                presenting,
            } => CallSignalBody::Media {
                audio_on: *audio_on,
                video_on: *video_on,
                presenting: *presenting,
            },
            CallSignalBodyJson::Direct {
                to_leaf,
                sdp,
                offer,
            } => CallSignalBody::Direct {
                to_leaf: *to_leaf,
                sdp: sdp.clone(),
                offer: *offer,
            },
            CallSignalBodyJson::MediaKey {
                generation,
                rotated,
                grants,
                started_at_ms,
                participation_hex,
            } => {
                check_grant_count(grants.len())?;
                check_started_at(*started_at_ms)?;
                let participation = participation_from_hex(participation_hex)?;
                let grants = grants
                    .iter()
                    .map(|grant| {
                        let enc = from_hex(&grant.enc_hex, "encHex")?;
                        let ciphertext = from_hex(&grant.ciphertext_hex, "ciphertextHex")?;
                        let enc_bytes = if enc.len() == CALL_MEDIA_PQ_ENC_BYTES {
                            CALL_MEDIA_PQ_ENC_BYTES
                        } else {
                            CALL_MEDIA_PUBLIC_KEY_BYTES
                        };
                        check_grant(&enc, &ciphertext, enc_bytes)?;
                        Ok(MediaGrant {
                            to_leaf: grant.to_leaf,
                            enc,
                            ciphertext,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                CallSignalBody::MediaKey {
                    generation: *generation,
                    rotated: *rotated,
                    grants,
                    started_at_ms: *started_at_ms,
                    participation,
                }
            }
            CallSignalBodyJson::Unknown => CallSignalBody::Unknown,
        };
        Ok(CallSignal {
            version: json.version,
            call_id,
            body,
        })
    }
}

/// Parse a signal from its JSON text.
pub fn signal_from_json(json: &str) -> Result<CallSignal> {
    let parsed: CallSignalJson = serde_json::from_str(json)
        .map_err(|err| Error::invalid(format!("could not read the call signal: {err}")))?;
    CallSignal::try_from(&parsed)
}

/// A signal as JSON text.
pub fn signal_to_json(signal: &CallSignal) -> Result<String> {
    serde_json::to_string(&CallSignalJson::from(signal))
        .map_err(|err| Error::invalid(format!("could not write the call signal: {err}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const ID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn all_bodies() -> Vec<CallSignalBody> {
        vec![
            CallSignalBody::Offer {
                media: CallMedia::Video,
                ring: true,
                created_at_ms: 1_789_516_800_000,
            },
            CallSignalBody::Offer {
                media: CallMedia::Audio,
                ring: false,
                created_at_ms: 0,
            },
            CallSignalBody::Answer,
            CallSignalBody::Hangup {
                reason: HangupReason::Normal,
            },
            CallSignalBody::Hangup {
                reason: HangupReason::NeedPermission,
            },
            CallSignalBody::Joined {
                participant_id: "p1".into(),
                session_id: "s1".into(),
                track_names: vec!["audio".into(), String::new(), "video".into()],
                leaf_index: 7,
                media_key: Vec::new(),
                started_at_ms: 0,
                media_key_pq: Vec::new(),
                participation: None,
            },
            CallSignalBody::Joined {
                participant_id: "p1".into(),
                session_id: String::new(),
                track_names: Vec::new(),
                leaf_index: 2,
                media_key: vec![0x42; CALL_MEDIA_PUBLIC_KEY_BYTES],
                started_at_ms: 1_789_516_800_123,
                media_key_pq: Vec::new(),
                participation: None,
            },
            CallSignalBody::MediaKey {
                generation: 3,
                rotated: true,
                grants: vec![
                    MediaGrant {
                        to_leaf: 0,
                        enc: vec![1; CALL_MEDIA_PUBLIC_KEY_BYTES],
                        ciphertext: vec![2; 80],
                    },
                    MediaGrant {
                        to_leaf: 5,
                        enc: vec![3; CALL_MEDIA_PUBLIC_KEY_BYTES],
                        ciphertext: vec![4; 80],
                    },
                ],
                started_at_ms: 1_789_516_800_123,
                participation: None,
            },
            CallSignalBody::MediaKey {
                generation: 0,
                rotated: false,
                grants: Vec::new(),
                started_at_ms: 0,
                participation: None,
            },
            CallSignalBody::Left {
                participant_id: "p1".into(),
            },
            CallSignalBody::RaiseHand { up: true },
            CallSignalBody::React {
                emoji: "🎉".into()
            },
            CallSignalBody::RemoteMute {
                target: "p2".into(),
            },
            CallSignalBody::Remove {
                target: "p3".into(),
            },
            CallSignalBody::Media {
                audio_on: true,
                video_on: false,
                presenting: true,
            },
            CallSignalBody::Direct {
                to_leaf: 0,
                sdp: "v=0\r\n".into(),
                offer: true,
            },
            CallSignalBody::Direct {
                to_leaf: 3,
                sdp: "v=0\r\n".into(),
                offer: false,
            },
        ]
    }

    #[test]
    fn every_body_round_trips_through_bytes_and_json() {
        for body in all_bodies() {
            let signal = CallSignal::new(ID, body);
            let bytes = encode_call_signal(&signal).unwrap();
            assert_eq!(decode_call_signal(&bytes).unwrap(), signal);
            let json = signal_to_json(&signal).unwrap();
            assert_eq!(signal_from_json(&json).unwrap(), signal, "{json}");
        }
    }

    #[test]
    fn unknown_fields_and_types_are_tolerated() {
        let signal = CallSignal::new(ID, CallSignalBody::Answer);
        let mut bytes = encode_call_signal(&signal).unwrap();
        // field 99, varint 5; field 98, fixed32; field 97, fixed64.
        bytes.extend_from_slice(&[0x98, 0x06, 0x05]);
        bytes.extend_from_slice(&[0x95, 0x06, 1, 2, 3, 4]);
        bytes.extend_from_slice(&[0x89, 0x06, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(decode_call_signal(&bytes).unwrap(), signal);

        // A body this build does not know: field 40, length 2.
        let mut newer = Vec::new();
        put_uint(&mut newer, 1, 2);
        put_bytes(&mut newer, 2, &ID);
        put_bytes(&mut newer, 40, &[0x08, 0x01]);
        let decoded = decode_call_signal(&newer).unwrap();
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.body, CallSignalBody::Unknown);
    }

    #[test]
    fn malformed_signals_are_refused() {
        assert!(decode_call_signal(&[]).is_err(), "no version");
        assert!(decode_call_signal(&[0x08, 0x01]).is_err(), "no call id");
        assert!(
            decode_call_signal(&[0x08, 0x01, 0x12, 0x01, 0x00]).is_err(),
            "short id"
        );
        assert!(decode_call_signal(&[0x08]).is_err(), "truncated varint");
        assert!(decode_call_signal(&[0x0b]).is_err(), "group wire type");
        assert!(encode_call_signal(&CallSignal::new(ID, CallSignalBody::Unknown)).is_err());
        let empty = CallSignalBody::Direct {
            to_leaf: 1,
            sdp: String::new(),
            offer: true,
        };
        assert!(
            encode_call_signal(&CallSignal::new(ID, empty)).is_err(),
            "no SDP"
        );
        let huge = CallSignalBody::Direct {
            to_leaf: 1,
            sdp: "a".repeat(MAX_CALL_SDP_BYTES + 1),
            offer: true,
        };
        assert!(
            encode_call_signal(&CallSignal::new(ID, huge)).is_err(),
            "SDP too long"
        );
    }

    #[test]
    fn a_media_key_is_mls_lane_not_urgent_and_bounded() {
        let grant = |enc: usize, ct: usize| MediaGrant {
            to_leaf: 1,
            enc: vec![1; enc],
            ciphertext: vec![2; ct],
        };
        let body = CallSignalBody::MediaKey {
            generation: 1,
            rotated: false,
            grants: vec![grant(32, 48)],
            started_at_ms: 0,
            participation: None,
        };
        assert!(body.is_mls_lane());
        assert!(!body.is_urgent());
        for bad in [grant(31, 48), grant(33, 48), grant(32, 0)] {
            let body = CallSignalBody::MediaKey {
                generation: 1,
                rotated: false,
                grants: vec![bad],
                started_at_ms: 0,
                participation: None,
            };
            assert!(encode_call_signal(&CallSignal::new(ID, body)).is_err());
        }
        let too_many = CallSignalBody::MediaKey {
            generation: 1,
            rotated: true,
            grants: vec![grant(32, 16); MAX_CALL_MEDIA_GRANTS + 1],
            started_at_ms: 0,
            participation: None,
        };
        assert!(encode_call_signal(&CallSignal::new(ID, too_many)).is_err());
        let short_key = CallSignalBody::Joined {
            participant_id: "p".into(),
            session_id: String::new(),
            track_names: Vec::new(),
            leaf_index: 1,
            media_key: vec![9; 31],
            started_at_ms: 0,
            media_key_pq: Vec::new(),
            participation: None,
        };
        assert!(encode_call_signal(&CallSignal::new(ID, short_key)).is_err());
    }

    #[test]
    fn a_direct_signal_is_mls_lane_and_not_urgent() {
        let body = CallSignalBody::Direct {
            to_leaf: 2,
            sdp: "v=0\r\n".into(),
            offer: false,
        };
        assert!(body.is_mls_lane());
        assert!(!body.is_urgent());
    }

    #[test]
    fn a_participation_mark_round_trips_and_is_bounded() {
        let mark = Participation {
            id: [7; 16],
            seq: 42,
        };
        for body in [
            CallSignalBody::Joined {
                participant_id: "p".into(),
                session_id: String::new(),
                track_names: Vec::new(),
                leaf_index: 1,
                media_key: vec![9; CALL_MEDIA_PUBLIC_KEY_BYTES],
                started_at_ms: 5,
                media_key_pq: Vec::new(),
                participation: Some(mark),
            },
            CallSignalBody::MediaKey {
                generation: 1,
                rotated: false,
                grants: Vec::new(),
                started_at_ms: 5,
                participation: Some(mark),
            },
        ] {
            let signal = CallSignal::new(ID, body);
            let bytes = encode_call_signal(&signal).unwrap();
            assert_eq!(decode_call_signal(&bytes).unwrap(), signal);
            let json = signal_to_json(&signal).unwrap();
            assert!(json.contains("participationHex"), "{json}");
            assert_eq!(signal_from_json(&json).unwrap(), signal, "{json}");
        }
        assert_eq!(Participation::from_bytes(&mark.to_bytes()).unwrap(), mark);
        assert!(Participation::from_bytes(&[0; 23]).is_err());
        let zero = Participation {
            id: [1; 16],
            seq: 0,
        };
        assert!(Participation::from_bytes(&zero.to_bytes()).is_err());
        let huge = Participation {
            id: [1; 16],
            seq: 1 << 53,
        };
        assert!(Participation::from_bytes(&huge.to_bytes()).is_err());
    }

    #[test]
    fn a_live_signature_is_the_last_field_and_older_readers_skip_it() {
        let signal = CallSignal::new(
            ID,
            CallSignalBody::Left {
                participant_id: "p".into(),
            },
        );
        let unsigned = encode_call_signal(&signal).unwrap();
        assert_eq!(
            split_live_signature(&unsigned).unwrap(),
            (&unsigned[..], None)
        );

        let mut signed = unsigned.clone();
        append_live_signature(&mut signed, &[3; CALL_LIVE_SIGNATURE_BYTES]);
        let (body, signature) = split_live_signature(&signed).unwrap();
        assert_eq!(body, &unsigned[..]);
        assert_eq!(signature, Some([3; CALL_LIVE_SIGNATURE_BYTES]));
        // A reader that predates the signature skips it as an unknown field.
        assert_eq!(decode_call_signal(&signed).unwrap(), signal);

        // Twice, short, or followed by another field: refused.
        let mut twice = signed.clone();
        append_live_signature(&mut twice, &[4; CALL_LIVE_SIGNATURE_BYTES]);
        assert!(split_live_signature(&twice).is_err());
        let mut short = unsigned.clone();
        put_bytes(&mut short, CALL_LIVE_SIGNATURE_FIELD, &[3; 63]);
        assert!(split_live_signature(&short).is_err());
        let mut trailing = signed.clone();
        put_uint(&mut trailing, 99, 1);
        assert!(split_live_signature(&trailing).is_err());
    }
}
