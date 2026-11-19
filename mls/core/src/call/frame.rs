// SPDX-License-Identifier: MIT
//! The two lanes a call signal travels on (docs/calls.md §Signaling).
//!
//! Every call signal is the inner bytes of an
//! [`ENVELOPE_KIND_CALL`](crate::envelope::ENVELOPE_KIND_CALL) envelope, and
//! its first byte names the lane:
//!
//! ```text
//! lane 1, MLS:  0x01 ‖ MLSMessage            (a PrivateMessage, content type application,
//!                                             whose plaintext is the encoded CallSignal)
//! lane 2, live: 0x02 ‖ nonce (12) ‖ AES-256-GCM(live_key, nonce, aad = 0x02,
//!                                   u32be(sender_leaf) ‖ u64be(sent_at_ms) ‖
//!                                   u16be(len) ‖ CallSignal ‖ 0x00… to a multiple of 128)
//! live_key = MLS-Exporter(G, "peachy call live v1", context = "", 32)
//! ```
//!
//! **The MLS lane** is sender-authenticated by the group: a receiver knows
//! which device sent a signal and at which leaf. [`crate::Client::seal_call_signal`]
//! always puts `Offer`, `Answer`, `Hangup`, `Remove`, `Direct` and the
//! in-call controls (`RaiseHand`, `React`, `RemoteMute`, `Media`) here, so a
//! member cannot ring as somebody else, cannot forge "answered elsewhere" to
//! silence a ring, an admin's `Remove` can be checked against who sent it,
//! and every control names its sender (docs/calls.md §In-call
//! controls). These go through the mailbox (`SendSealed`; `Offer`, `Answer`
//! and `Hangup` marked urgent, nothing else), so a locked phone gets them.
//! [`crate::Client::seal_call_signal_on_mls_lane`] sends ANY signal here,
//! since authentication only adds, and **each participant's FIRST `Joined` in
//! an epoch** must go this way (docs/calls.md §Disagreements,
//! D10). It binds that sender's media session and tracks to its leaf, and the
//! receiver checks its `leafIndex` is the sender's own leaf. So a member can
//! put frames on another's tile only with the media server's help.
//!
//! **The live lane** carries `Joined` heartbeats only, relayed to open
//! streams the way typing is: never stored, never pushed. It is keyed off the
//! epoch's exporter rather than the application ratchet for exactly the
//! reasons typing is (docs/sealed-messages.md §The key is the epoch's exporter
//! secret, not the application ratchet): a 10-second `Joined` heartbeat on the
//! ratchet would burn a generation per beat for every member, and a device
//! asleep through a long call would come back past `maximum_forward_distance`,
//! unable to read real messages. A live frame is signed by the leaf it claims
//! (below), but names no MLS sender a client could bind, so a live
//! `Joined` only refreshes a participant a signed one already bound, and
//! changes nothing that binding holds. On open the core refuses a live
//! `Joined` whose `leafIndex` is not the leaf its own frame claims, and any
//! live frame claiming a leaf the tree does not hold.
//!
//! A receiver derives the live key at its own current epoch only — there is
//! no grace window for live signals (threat model R-K9, D7): a frame from a
//! sender one epoch away fails to open and is dropped, and the next heartbeat
//! arrives ten seconds later. A removed member therefore cannot inject live
//! signals after the removal is merged. The grace window
//! ([`super::CALL_KEY_GRACE_MS`]) is for media frame keys alone.
//!
//! **Every live frame carries its sender's leaf and a stamp**, inside the
//! AEAD ([`LiveStamp`]), and receivers keep a replay window over them
//! ([`super::replay`]; threat model D3): a recorded heartbeat is refused
//! while its stamp is remembered. The server sets the agreed clock, so once
//! a stamp is forgotten it can move a device's clock back and have that
//! frame opened again within its epoch (docs/calls.md §The live
//! lane's replay window).
//!
//! **A live frame is signed by its sender's leaf key** (the Ed25519 key its
//! credential binds and its MLS messages are signed with), as a typing frame
//! is (docs/sealed-messages.md §Typing inside the group): the
//! signature covers the group, the epoch, the claimed leaf, the stamp and the
//! encoded signal ([`live_signature_statement`]), and travels as the signal's
//! last top-level field ([`super::signal::CALL_LIVE_SIGNATURE_FIELD`]). A
//! receiver verifies it under the key of the leaf the frame claims and
//! refuses a frame without one, so a live frame is attributed: a member
//! cannot write one in another member's name.
//!
//! The lane is checked on open as well as on seal: an `Offer`, `Answer`,
//! `Hangup`, `Remove`, `Direct`, `Left` or in-call control arriving on the
//! live lane is refused, so a live frame can never ring, stop a ring, hang
//! up, remove anyone, drop a participant, or speak for a participant.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::error::{Error, Result};

/// The MLS lane's first byte.
pub const CALL_LANE_MLS: u8 = 1;
/// The live lane's first byte.
pub const CALL_LANE_LIVE: u8 = 2;
/// The `authenticated_data` of every call signal on the MLS lane. It is not
/// a content hint (`crate::hint`): a hint starts `0x70 0x01`, so any reader
/// takes these bytes as "no hint", exactly as it takes the empty AAD that
/// builds before it sent, and no reader checks them. They are there for
/// length alone. A hinted message carries nineteen AAD bytes (the hint's
/// three and the author's commitment's sixteen, `crate::hint` §The author's
/// commitment); a call signal carries the lane byte ahead of its message, and
/// the lane byte plus these eighteen make the same nineteen, so on the wire a
/// call signal is as long as a message, reaction or receipt whose plaintext
/// falls in the same padding block, and its length does not say it is a call.
/// (Builds before the commitment sent `0x63 0x01` alone, beside a three-byte
/// hint.)
pub const CALL_LANE_AAD: [u8; 18] = [0x63, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// The exporter label of the live lane's key.
pub const CALL_LIVE_EXPORTER_LABEL: &str = "peachy call live v1";
/// The live key's length.
pub const CALL_LIVE_KEY_BYTES: usize = 32;
/// A live frame's plaintext is padded to a multiple of this, so a reaction
/// and a heartbeat are one size.
pub const CALL_LIVE_PADDING_BLOCK: usize = 128;

/// The domain of the statement a live frame's signature covers.
pub const CALL_LIVE_SIGNATURE_DOMAIN: &str = "peachy call live signature v1";
/// What a live frame's signature covers: the domain, `0x00`, the group id
/// (4-byte length first), the epoch, the claimed leaf, the stamp, and the
/// encoded signal without its signature field.
pub fn live_signature_statement(
    group_id: &[u8],
    epoch: u64,
    stamp: LiveStamp,
    unsigned_signal: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        CALL_LIVE_SIGNATURE_DOMAIN.len() + 25 + group_id.len() + unsigned_signal.len(),
    );
    out.extend_from_slice(CALL_LIVE_SIGNATURE_DOMAIN.as_bytes());
    out.push(0);
    out.extend_from_slice(&(group_id.len() as u32).to_be_bytes());
    out.extend_from_slice(group_id);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&stamp.sender_leaf.to_be_bytes());
    out.extend_from_slice(&stamp.sent_at_ms.to_be_bytes());
    out.extend_from_slice(unsigned_signal);
    out
}

/// Whether `public_key` (a leaf's 32-byte Ed25519 key) signed this live
/// frame. `verify_strict`, as every signature this crate checks outside MLS.
pub fn live_signature_holds(
    public_key: &[u8],
    group_id: &[u8],
    epoch: u64,
    stamp: LiveStamp,
    unsigned_signal: &[u8],
    signature: &[u8; super::signal::CALL_LIVE_SIGNATURE_BYTES],
) -> bool {
    let Ok(key_bytes) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    key.verify_strict(
        &live_signature_statement(group_id, epoch, stamp, unsigned_signal),
        &ed25519_dalek::Signature::from_bytes(signature),
    )
    .is_ok()
}

const NONCE_BYTES: usize = 12;
const STAMP_BYTES: usize = 4 + 8;

/// What a live frame says about itself, inside its AEAD: the leaf its sender
/// claims and the sender's strictly increasing millisecond stamp. Receivers
/// check it against their replay window ([`super::replay`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveStamp {
    pub sender_leaf: u32,
    pub sent_at_ms: u64,
}

/// Which lane a call envelope's inner bytes are on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallLane {
    Mls,
    Live,
}

impl CallLane {
    /// The lane named by an envelope's inner bytes, and the rest of them.
    pub fn split(inner: &[u8]) -> Result<(CallLane, &[u8])> {
        match inner.split_first() {
            Some((&CALL_LANE_MLS, rest)) => Ok((CallLane::Mls, rest)),
            Some((&CALL_LANE_LIVE, rest)) => Ok((CallLane::Live, rest)),
            Some((other, _)) => Err(Error::invalid(format!("{other} is not a call lane"))),
            None => Err(Error::invalid("a call envelope carries a lane")),
        }
    }

    /// Its name in the JSON forms.
    pub fn name(self) -> &'static str {
        match self {
            CallLane::Mls => "mls",
            CallLane::Live => "live",
        }
    }
}

fn cipher(key: &[u8]) -> Result<Aes256Gcm> {
    if key.len() != CALL_LIVE_KEY_BYTES {
        return Err(Error::invalid(format!(
            "a live call key is {CALL_LIVE_KEY_BYTES} bytes"
        )));
    }
    Aes256Gcm::new_from_slice(key).map_err(|_| Error::invalid("an AES-256 key must be 32 bytes"))
}

/// Seal an encoded call signal as a live frame under `key`, stamped, and the
/// given nonce — the fixture's deterministic door. Returns the envelope's
/// inner bytes, lane byte first. A nonce used twice under one live key is
/// AES-GCM's one fatal misuse, so this is compiled only for the golden
/// fixture, the fuzz targets and the crate's own tests; every client seals
/// through [`seal_live_frame`].
#[cfg(any(test, feature = "fixture"))]
pub fn seal_live_frame_with_nonce(
    key: &[u8],
    stamp: LiveStamp,
    signal: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    seal_live_with_nonce(key, stamp, signal, nonce)
}

fn seal_live_with_nonce(
    key: &[u8],
    stamp: LiveStamp,
    signal: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_BYTES {
        return Err(Error::invalid("a live call frame's nonce is 12 bytes"));
    }
    let len = u16::try_from(signal.len())
        .map_err(|_| Error::invalid("a live call frame carries at most 65535 bytes"))?;
    // Sized before its first byte, so no growth leaves a copy behind, and
    // wiped once sealed.
    let mut padded = zeroize::Zeroizing::new(Vec::with_capacity(
        STAMP_BYTES + signal.len() + CALL_LIVE_PADDING_BLOCK,
    ));
    padded.extend_from_slice(&stamp.sender_leaf.to_be_bytes());
    padded.extend_from_slice(&stamp.sent_at_ms.to_be_bytes());
    padded.extend_from_slice(&len.to_be_bytes());
    padded.extend_from_slice(signal);
    let rem = padded.len() % CALL_LIVE_PADDING_BLOCK;
    if rem != 0 {
        let to = padded.len() + CALL_LIVE_PADDING_BLOCK - rem;
        padded.resize(to, 0);
    }
    let sealed = cipher(key)?
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: padded.as_slice(),
                aad: &[CALL_LANE_LIVE],
            },
        )
        .map_err(|_| Error::invalid("the live call frame did not seal"))?;
    let mut out = Vec::with_capacity(1 + NONCE_BYTES + sealed.len());
    out.push(CALL_LANE_LIVE);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Seal an encoded call signal as a live frame under `key`, stamped, and a
/// fresh random nonce. Returns the envelope's inner bytes, lane byte first.
pub fn seal_live_frame(key: &[u8], stamp: LiveStamp, signal: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce)
        .map_err(|err| Error::invalid(format!("no randomness for a call frame nonce: {err}")))?;
    seal_live_with_nonce(key, stamp, signal, &nonce)
}

/// Open a live frame (the envelope's inner bytes, lane byte first) and return
/// its stamp and the encoded call signal inside. The stamp is NOT checked
/// here: that needs the receiver's window ([`super::replay`]).
pub fn open_live_frame(key: &[u8], inner: &[u8]) -> Result<(LiveStamp, Vec<u8>)> {
    let (lane, rest) = CallLane::split(inner)?;
    if lane != CallLane::Live {
        return Err(Error::invalid("that call envelope is not a live frame"));
    }
    if rest.len() < NONCE_BYTES {
        return Err(Error::invalid("a live call frame carries a nonce"));
    }
    let (nonce, sealed) = rest.split_at(NONCE_BYTES);
    // Wiped once the signal is copied out of it.
    let padded = zeroize::Zeroizing::new(
        cipher(key)?
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: &[CALL_LANE_LIVE],
                },
            )
            .map_err(|_| Error::invalid("the live call frame did not open"))?,
    );
    let (leaf, rest) = padded
        .split_first_chunk::<4>()
        .ok_or_else(|| Error::invalid("a live call frame carries a stamp"))?;
    let (sent_at, rest) = rest
        .split_first_chunk::<8>()
        .ok_or_else(|| Error::invalid("a live call frame carries a stamp"))?;
    let stamp = LiveStamp {
        sender_leaf: u32::from_be_bytes(*leaf),
        sent_at_ms: u64::from_be_bytes(*sent_at),
    };
    let (len, body) = match rest.split_first_chunk::<2>() {
        Some((len, body)) => (usize::from(u16::from_be_bytes(*len)), body),
        None => return Err(Error::invalid("a live call frame carries a length")),
    };
    let (signal, padding) = body
        .split_at_checked(len)
        .ok_or_else(|| Error::invalid("a live call frame's length runs past its end"))?;
    if padding.iter().any(|b| *b != 0) {
        return Err(Error::invalid("a live call frame's padding is not zero"));
    }
    Ok((stamp, signal.to_vec()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_live_frame_round_trips_and_hides_its_length() {
        let key = [9u8; 32];
        let stamp = LiveStamp {
            sender_leaf: 3,
            sent_at_ms: 1_789_516_800_000,
        };
        let short = seal_live_frame(&key, stamp, b"a").unwrap();
        let long = seal_live_frame(&key, stamp, &[7u8; 100]).unwrap();
        assert_eq!(short.len(), long.len());
        assert_eq!(
            open_live_frame(&key, &short).unwrap(),
            (stamp, b"a".to_vec())
        );
        assert_eq!(
            open_live_frame(&key, &long).unwrap(),
            (stamp, vec![7u8; 100])
        );
        assert!(open_live_frame(&[8u8; 32], &short).is_err());
        let mut mls = short.clone();
        mls[0] = CALL_LANE_MLS;
        assert!(open_live_frame(&key, &mls).is_err());
    }
}
