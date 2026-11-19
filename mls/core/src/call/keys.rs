// SPDX-License-Identifier: MIT
//! The call key schedule (docs/calls.md §Keys).
//!
//! ```text
//! call_root(e) = MLS-Exporter(G, "peachy call v1", context = call_id (16), L = 32)
//! sender_key   = HKDF-Expand-SHA256(PRK = call_root(e),
//!                                   info = "peachy call sender" ‖ u32be(leaf_index), L = 16)
//! key_index    = e mod 256                       // the frame encryptor's key-ring slot
//! frame_key    = HKDF-SHA256(salt = "peachy call frame v1", IKM = sender_key,
//!                            info = 128 zero bytes, L = 16)   // AES-128-GCM
//! ```
//!
//! **v1 has no key-distribution message.** Every member of epoch `e` already
//! holds the exporter secret, so each derives every sender's key locally; a
//! device that is not a member of `e` derives nothing. A commit (add, remove,
//! self-update) moves `e`, and every device re-derives. So v1 makes the GROUP
//! the key boundary, not the call: a member that never joins derives every
//! participant's key, and leaving the call changes no key.
//!
//! **v2 makes the call the key boundary** (docs/calls.md §Participant
//! media keys), still bound to the epoch:
//!
//! ```text
//! call_root_v2(e) = MLS-Exporter(G, "peachy call v2", context = call_id (16), L = 32)
//! sender_key_v2   = HKDF-Expand-SHA256(PRK = HKDF-Extract(salt = call_root_v2(e), IKM = media_secret),
//!                                      info = "peachy call sender v2" ‖ u32be(leaf_index), L = 16)
//! advance(s)      = HKDF-Expand-SHA256(PRK = s, info = "peachy call media advance", L = 32)
//! key_index_v2    = ((e mod 16) << 4) | (generation mod 16)
//! ```
//!
//! `media_secret` is 32 random bytes per participant device and call, which
//! only participants receive ([`super::media`]). `frame_key` is the same
//! derivation in both versions.
//!
//! **`sender_key` is what a client hands its frame encryptor's key provider**
//! (`setKey(participant, key_index, sender_key)`), 16 bytes on every client:
//! one platform's frame-encryption API is AES-128 whatever length of key
//! material it is given, so every client uses 128-bit keys.
//!
//! **`frame_key` is what the key provider turns it into.** The WebRTC frame
//! encryptor never encrypts with the bytes it is handed: its per-participant
//! key handler derives the AES key from them with the key provider's ratchet
//! salt and its key-derivation algorithm (PBKDF2 with 100,000 iterations by
//! default, or HKDF). Peachy configures **HKDF** — the material is already a
//! uniformly random exporter output, so stretching it buys nothing and costs
//! 100,000 HMACs per sender per epoch — and its own salt. The media library's
//! HKDF key derivation is: SHA-256, the salt's UTF-8 bytes, `info` a 128-byte
//! zero buffer, a 128-bit AES-GCM key. [`call_frame_key`] is exactly that, so a
//! client that does its own frame encryption (the web worker) reaches the
//! bytes a native encryptor uses, and the fixture's `frameKeyHex` rows pin it
//! (docs/calls.md §Keys as built).
//!
//! The key provider is configured with `ratchetWindowSize = 0` (we never
//! ratchet: an epoch change is the rekey), `sharedKeyMode = false` (one key
//! per sender), and `keyRingSize = 256` so that [`call_key_index`]'s whole
//! byte addresses a slot.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};

/// The MLS exporter label a call's root is derived under. Its own label, so
/// no other feature's exporter output (typing, the send key) is ever a call
/// key, and the reverse.
pub const CALL_EXPORTER_LABEL: &str = "peachy call v1";
/// The exporter output length, `L` in `MLS-Exporter(G, label, call_id, L)`.
pub const CALL_ROOT_BYTES: usize = 32;
/// The HKDF info prefix for a sender key; the leaf index follows as u32be.
pub const CALL_SENDER_INFO: &[u8] = b"peachy call sender";
/// A sender key: AES-128 material, on every client.
pub const CALL_SENDER_KEY_BYTES: usize = 16;
/// The frame encryptor's key-provider ratchet salt, as UTF-8 bytes.
pub const CALL_FRAME_RATCHET_SALT: &str = "peachy call frame v1";
/// The length of the zero `info` the frame key's HKDF derivation uses.
pub const CALL_FRAME_KEY_INFO_BYTES: usize = 128;
/// The AES-128-GCM key a frame encryptor encrypts frames with.
pub const CALL_FRAME_KEY_BYTES: usize = 16;
/// The key provider's ring size: one slot per value of [`call_key_index`].
pub const CALL_KEY_RING_SIZE: usize = 256;
/// How long a client keeps the PREVIOUS epoch's keys in the ring after an
/// epoch change, to decrypt frames already in flight (docs/calls.md
/// §Keys). Media frame keys only: the live-signal key is never kept past an
/// epoch change (docs/calls.md, R-K9).
pub const CALL_KEY_GRACE_MS: u64 = 10_000;

/// How often EVERY device in a group call commits its own `self_update`,
/// staggered by its rank among the participants' leaves
/// ([`call_self_update_offset_ms`]; docs/calls.md §Keys as built). A
/// direct 1:1 call runs no in-call self-update. A commit heals only the
/// committer's leaf, so post-compromise security during a call needs each
/// participant to update its own (docs/calls.md, R-K4 and D2).
pub const CALL_SELF_UPDATE_INTERVAL_MS: u64 = 600_000;

/// The stagger of a participant's in-call self-updates: it commits its own
/// `self_update` at `joined + offset + k * CALL_SELF_UPDATE_INTERVAL_MS` for
/// k = 1, 2, …, so N devices do not commit at once. `rank` is this device's
/// position among the call's participants by ascending leaf index (0-based),
/// `participants` their count: the offset is
/// `(INTERVAL / max(participants, 1)) × min(rank, max(participants, 1) − 1)`,
/// dividing first. Pure; every client computes the same schedule.
pub fn call_self_update_offset_ms(rank: u32, participants: u32) -> u64 {
    let participants = u64::from(participants.max(1));
    CALL_SELF_UPDATE_INTERVAL_MS / participants * u64::from(rank).min(participants - 1)
}

/// The v2 exporter label: its own label, so a v1 key and a v2 key are never
/// the same bytes.
pub const CALL_EXPORTER_LABEL_V2: &str = "peachy call v2";
/// The HKDF info prefix for a v2 sender key; the leaf index follows as u32be.
pub const CALL_SENDER_INFO_V2: &[u8] = b"peachy call sender v2";
/// A participant's media secret.
pub const CALL_MEDIA_SEED_BYTES: usize = 32;
/// The HKDF info that advances a media secret one generation.
pub const CALL_MEDIA_ADVANCE_INFO: &[u8] = b"peachy call media advance";
/// How long a participant keeps sending under its previous secret after it
/// rotates, so the remaining participants hold the new one before the first
/// frame under it arrives.
pub const CALL_MEDIA_ROTATE_DELAY_MS: u64 = 5_000;
/// The most generations a receiver advances a sender's secret on its own, on
/// one `MediaKey` that announces an advance.
pub const CALL_MEDIA_MAX_ADVANCE: u32 = 64;

/// One sender's v2 key: the epoch's v2 call root and the sender's media
/// secret at one generation, bound to its leaf.
pub fn call_sender_key_v2(
    call_root: &[u8],
    media_secret: &[u8],
    leaf_index: u32,
) -> Result<[u8; CALL_SENDER_KEY_BYTES]> {
    if call_root.len() != CALL_ROOT_BYTES {
        return Err(Error::invalid(format!(
            "a call root is {CALL_ROOT_BYTES} bytes, not {}",
            call_root.len()
        )));
    }
    if media_secret.len() != CALL_MEDIA_SEED_BYTES {
        return Err(Error::invalid(format!(
            "a media secret is {CALL_MEDIA_SEED_BYTES} bytes, not {}",
            media_secret.len()
        )));
    }
    let hk = Hkdf::<Sha256>::new(Some(call_root), media_secret);
    let mut info = Vec::with_capacity(CALL_SENDER_INFO_V2.len() + 4);
    info.extend_from_slice(CALL_SENDER_INFO_V2);
    info.extend_from_slice(&leaf_index.to_be_bytes());
    let mut key = [0u8; CALL_SENDER_KEY_BYTES];
    hk.expand(&info, &mut key)
        .map_err(|_| Error::invalid("HKDF refused a 16-byte output"))?;
    Ok(key)
}

/// A media secret one generation on. One-way: whoever holds the result
/// cannot compute the secret it came from.
pub fn call_media_advance(media_secret: &[u8]) -> Result<[u8; CALL_MEDIA_SEED_BYTES]> {
    if media_secret.len() != CALL_MEDIA_SEED_BYTES {
        return Err(Error::invalid(format!(
            "a media secret is {CALL_MEDIA_SEED_BYTES} bytes, not {}",
            media_secret.len()
        )));
    }
    let hk = Hkdf::<Sha256>::from_prk(media_secret)
        .map_err(|_| Error::invalid("a media secret is too short to be an HKDF PRK"))?;
    let mut next = [0u8; CALL_MEDIA_SEED_BYTES];
    hk.expand(CALL_MEDIA_ADVANCE_INFO, &mut next)
        .map_err(|_| Error::invalid("HKDF refused a 32-byte output"))?;
    Ok(next)
}

/// The frame encryptor's key-ring slot for a v2 key: the epoch's low four
/// bits, then the generation's. A receiver keeps a separate ring per sender,
/// so the slot names one (epoch, generation) of that sender while the
/// previous epoch's grace window and a few generations are live at once.
pub fn call_key_index_v2(epoch: u64, generation: u32) -> u8 {
    (((epoch % 16) as u8) << 4) | ((generation % 16) as u8)
}

/// One sender's 16-byte key from the epoch's call root.
///
/// `call_root` is `MLS-Exporter(G, "peachy call v1", call_id, 32)` —
/// [`crate::Client::call_keys`] derives it from a real group; the fixture
/// hands it in directly.
pub fn call_sender_key(call_root: &[u8], leaf_index: u32) -> Result<[u8; CALL_SENDER_KEY_BYTES]> {
    if call_root.len() != CALL_ROOT_BYTES {
        return Err(Error::invalid(format!(
            "a call root is {CALL_ROOT_BYTES} bytes, not {}",
            call_root.len()
        )));
    }
    let hk = Hkdf::<Sha256>::from_prk(call_root)
        .map_err(|_| Error::invalid("a call root is too short to be an HKDF PRK"))?;
    let mut info = Vec::with_capacity(CALL_SENDER_INFO.len() + 4);
    info.extend_from_slice(CALL_SENDER_INFO);
    info.extend_from_slice(&leaf_index.to_be_bytes());
    let mut key = [0u8; CALL_SENDER_KEY_BYTES];
    hk.expand(&info, &mut key)
        .map_err(|_| Error::invalid("HKDF refused a 16-byte output"))?;
    Ok(key)
}

/// The frame encryptor's key-ring slot for epoch `epoch`: `e mod 256`. It rides in
/// every encrypted frame's trailer, so a receiver picks the right epoch's key
/// for a frame sent just before or after a commit.
pub fn call_key_index(epoch: u64) -> u8 {
    (epoch % CALL_KEY_RING_SIZE as u64) as u8
}

/// The AES-128-GCM key a frame encryptor derives from a sender key under
/// Peachy's key-provider settings (HKDF, [`CALL_FRAME_RATCHET_SALT`]). See the
/// module header for these parameters.
pub fn call_frame_key(sender_key: &[u8]) -> Result<[u8; CALL_FRAME_KEY_BYTES]> {
    if sender_key.len() != CALL_SENDER_KEY_BYTES {
        return Err(Error::invalid(format!(
            "a call sender key is {CALL_SENDER_KEY_BYTES} bytes, not {}",
            sender_key.len()
        )));
    }
    let hk = Hkdf::<Sha256>::new(Some(CALL_FRAME_RATCHET_SALT.as_bytes()), sender_key);
    let mut key = [0u8; CALL_FRAME_KEY_BYTES];
    hk.expand(&[0u8; CALL_FRAME_KEY_INFO_BYTES], &mut key)
        .map_err(|_| Error::invalid("HKDF refused a 16-byte output"))?;
    Ok(key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_leaf_gets_its_own_key() {
        let root = [7u8; 32];
        let a = call_sender_key(&root, 0).unwrap();
        let b = call_sender_key(&root, 1).unwrap();
        assert_ne!(a, b);
        assert_eq!(a, call_sender_key(&root, 0).unwrap());
    }

    #[test]
    fn a_root_of_the_wrong_length_is_refused() {
        assert!(call_sender_key(&[0u8; 16], 0).is_err());
        assert!(call_sender_key(&[0u8; 33], 0).is_err());
        assert!(call_frame_key(&[0u8; 32]).is_err());
    }

    #[test]
    fn a_v2_key_needs_the_media_secret_and_differs_from_v1() {
        let root = [7u8; 32];
        let secret = [1u8; 32];
        let v2 = call_sender_key_v2(&root, &secret, 0).unwrap();
        assert_ne!(v2, call_sender_key(&root, 0).unwrap());
        assert_ne!(v2, call_sender_key_v2(&root, &[2u8; 32], 0).unwrap());
        assert_ne!(v2, call_sender_key_v2(&root, &secret, 1).unwrap());
        assert_ne!(v2, call_sender_key_v2(&[8u8; 32], &secret, 0).unwrap());
        let next = call_media_advance(&secret).unwrap();
        assert_ne!(next, secret);
        assert_ne!(
            call_sender_key_v2(&root, &next, 0).unwrap(),
            v2,
            "an advance changes the key"
        );
        assert!(call_sender_key_v2(&root, &[0u8; 16], 0).is_err());
        assert!(call_media_advance(&[0u8; 16]).is_err());
    }

    #[test]
    fn the_v2_key_index_is_epoch_then_generation() {
        assert_eq!(call_key_index_v2(0, 0), 0x00);
        assert_eq!(call_key_index_v2(1, 2), 0x12);
        assert_eq!(call_key_index_v2(17, 18), 0x12);
        assert_eq!(call_key_index_v2(u64::MAX, u32::MAX), 0xff);
    }

    #[test]
    fn the_key_index_is_the_epoch_mod_256() {
        assert_eq!(call_key_index(0), 0);
        assert_eq!(call_key_index(255), 255);
        assert_eq!(call_key_index(256), 0);
        assert_eq!(call_key_index(u64::MAX), 255);
    }
}
