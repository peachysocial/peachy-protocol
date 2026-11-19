// SPDX-License-Identifier: MIT
//! Calls: the key schedule, the signaling codec and the ring-state reducer
//! (docs/calls.md §Keys, §Signaling, §Ringing).
//!
//! A call is a room that a sealed chat opens. Its media keys come out of that
//! chat's MLS group, so the devices that can hear it are exactly the devices
//! that can read the chat. Everything here is shared by every client
//! through the bindings; each client owns only its WebRTC wiring and its UI.
//!
//! - [`keys`] — `call_root(e) = MLS-Exporter(G, "peachy call v1", call_id, 32)`,
//!   one 16-byte sender key per leaf, the frame encryptor's key-ring slot,
//!   the AES key its key provider derives from what we hand it, and the
//!   stagger of the in-call self-updates.
//! - [`signal`] — the `Offer` / `Answer` / `Hangup` / in-call / `Direct`
//!   messages: a small, versioned protobuf of our own, tolerant of fields and
//!   message types a newer build adds.
//! - [`frame`] — the two lanes a call signal travels on inside an
//!   [`ENVELOPE_KIND_CALL`](crate::envelope::ENVELOPE_KIND_CALL) envelope: the
//!   MLS lane (an application message, sender-authenticated, through the
//!   mailbox) and the live lane (an exporter-keyed frame relayed like typing,
//!   never stored).
//! - [`replay`] — the live lane's replay window: the stamps accepted per
//!   (group, sender leaf), each kept until the clock bound refuses it.
//! - [`ring`] — a pure reducer from (state, event) to (state, effects) for
//!   ringing, busy, "answered, declined or busy elsewhere", hangup reasons and
//!   the 16-person ring cap.
//! - [`session`] — the [`crate::Client`] doors that tie them to a real group:
//!   the epoch's key ring, and sealing and opening a call envelope.
//!
//! `mls/fixtures/calls.json` pins all of it, replayed through the fixture door
//! (`kind: "call"`) in Rust, JavaScript, Swift and Kotlin.

pub mod frame;
pub mod keys;
pub mod media;
pub mod replay;
pub mod ring;
pub mod session;
pub mod signal;

#[cfg(any(test, feature = "fixture"))]
pub use frame::seal_live_frame_with_nonce;
pub use frame::{
    live_signature_holds, live_signature_statement, open_live_frame, seal_live_frame, CallLane,
    LiveStamp, CALL_LANE_AAD, CALL_LANE_LIVE, CALL_LANE_MLS, CALL_LIVE_EXPORTER_LABEL,
    CALL_LIVE_KEY_BYTES, CALL_LIVE_PADDING_BLOCK, CALL_LIVE_SIGNATURE_DOMAIN,
};
pub use keys::{
    call_frame_key, call_key_index, call_key_index_v2, call_media_advance,
    call_self_update_offset_ms, call_sender_key, call_sender_key_v2, CALL_EXPORTER_LABEL,
    CALL_EXPORTER_LABEL_V2, CALL_FRAME_KEY_BYTES, CALL_FRAME_KEY_INFO_BYTES,
    CALL_FRAME_RATCHET_SALT, CALL_KEY_GRACE_MS, CALL_KEY_RING_SIZE, CALL_MEDIA_ADVANCE_INFO,
    CALL_MEDIA_MAX_ADVANCE, CALL_MEDIA_ROTATE_DELAY_MS, CALL_MEDIA_SEED_BYTES, CALL_ROOT_BYTES,
    CALL_SELF_UPDATE_INTERVAL_MS, CALL_SENDER_INFO, CALL_SENDER_INFO_V2, CALL_SENDER_KEY_BYTES,
};
#[cfg(any(test, feature = "fixture"))]
pub use media::open_call_media_grant;
pub use media::{
    call_media_grant_info, call_media_key_pair, call_media_pq_key_pair, seal_call_media_grant,
    CallMediaKeys, CallMediaParticipant, CallMediaSenderKey, OpenedMediaGrant, CALL_MEDIA_HPKE,
    CALL_MEDIA_HPKE_PQ, CALL_MEDIA_KEY_INFO, CALL_STATE_LOST,
};
pub use replay::{
    live_replay_steps_json, LiveReplayVerdict, LiveReplayWindow, CALL_LIVE_FORGET_MS,
    CALL_LIVE_MAX_SENDERS, CALL_LIVE_MAX_SKEW_MS,
};
pub use ring::{
    offer_is_fresh, ring_step, ring_step_json, should_ring, RingEffect, RingEvent, RingGate,
    RingOutcome, RingState, RingStep, RingTarget, CALL_OFFER_MAX_AGE_MS, CALL_OFFER_MAX_SKEW_MS,
    CALL_RING_CAP, CALL_RING_TIMEOUT_MS,
};
pub use session::{call_signal_is_urgent_json, CallKeys, CallSenderKey, OpenedCallSignal};
pub use signal::{
    append_live_signature, decode_call_signal, decode_media_grant_payload, encode_call_signal,
    encode_media_grant_payload, signal_from_json, signal_to_json, split_live_signature, CallMedia,
    CallSignal, CallSignalBody, CallSignalBodyJson, CallSignalJson, HangupReason, MediaGrant,
    MediaGrantJson, MediaGrantPayload, Participation, CALL_ID_BYTES, CALL_LIVE_SIGNATURE_BYTES,
    CALL_LIVE_SIGNATURE_FIELD, CALL_MEDIA_PQ_ENC_BYTES, CALL_MEDIA_PQ_PUBLIC_KEY_BYTES,
    CALL_MEDIA_PUBLIC_KEY_BYTES, CALL_PARTICIPATION_BYTES, CALL_SIGNAL_VERSION,
    MAX_CALL_MEDIA_GRANTS, MAX_CALL_SDP_BYTES, MAX_CALL_SIGNAL_BYTES,
};

/// Lower-case hex, for the JSON forms.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Hex in either case to bytes, naming `field` when it is not hex.
pub(crate) fn from_hex(hex: &str, field: &str) -> crate::error::Result<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(crate::error::Error::invalid(format!(
            "{field} is not hex: odd length"
        )));
    }
    bytes
        .chunks(2)
        .map(|pair| match pair {
            [hi, lo] => match (nibble(*hi), nibble(*lo)) {
                (Some(hi), Some(lo)) => Ok((hi << 4) | lo),
                _ => Err(crate::error::Error::invalid(format!("{field} is not hex"))),
            },
            _ => Err(crate::error::Error::invalid(format!("{field} is not hex"))),
        })
        .collect()
}
