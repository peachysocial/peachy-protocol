// SPDX-License-Identifier: MIT
//! The padded Welcome frame (docs/delivery.md §The padded Welcome frame).
//!
//! ## The frame
//!
//! ```text
//! raw    = MLSMessage(Welcome)                 starts 00 01 00 03
//! framed = ff 50 57 01 ‖ BE32(len) ‖ welcome ‖ 00…
//! ```
//!
//! A raw RFC 9420 message starts with its protocol version, `00 01`; the
//! frame's magic starts `ff`, which no MLS version byte is, so neither can be
//! read as the other. The zeros fill the frame to the target [`crate::commit_padding`] computes for
//! the add: the Welcome with its tree taken at a bound read from the tree's
//! shape alone (its width, member count and leaf sizes, every parent counted
//! filled) and the rest of the GroupInfo, the group state included, at its
//! true size, plus this header, rounded up to 256 bytes. The server parses
//! the Welcome to check that each of its cleartext KeyPackageRefs names a
//! package the directory handed out; it carries the frame as it carried the
//! raw bytes.
//!
//! Every Welcome is framed, and a raw Welcome is refused on join
//! ([`unframe_welcome`], called by `Client::join_from_welcome`), after it has
//! spent the key package it is sealed to, as every refused Welcome does.

//! ## The gap block
//!
//! A reseat (`Client::replace_member`) hands a seat back to the device that
//! held it, after its copy fell behind or forked. Envelopes sealed to that
//! device while it could not follow are keyed by epochs it never reached
//! (`crate::envelope` §Keyed by the epoch), so its Welcome carries those
//! epochs' envelope secrets, sealed to the epoch the Welcome opens:
//!
//! ```text
//! framed    = ff 50 57 02 ‖ BE32(len) ‖ welcome ‖ gap block ‖ 00…
//! gap block = nonce(12) ‖ AES-256-GCM(key, count ‖ (BE64(epoch) ‖ secret(32)) × count ‖ 00…) ‖ tag(16)
//! key       = MLS-Exporter("peachy welcome gap v1", group id, 32) of the new epoch
//! ```
//!
//! The block is always [`WELCOME_GAP_BLOCK_BYTES`] long, room for
//! [`WELCOME_GAP_EPOCHS`] epochs, so its length says nothing about how long
//! the device was away. Only the reseated device and the members of the new
//! epoch can open it, and only the epochs that device's seat was held through
//! go in: none from before it was (re)added, so a removed member gets nothing
//! sealed after its removal.
//!
//! `mls/fixtures/welcome-frame.json` pins the bytes, replayed through the
//! fixture door (`kind: "welcome_frame"`) in every binding.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::error::{Error, Result};

/// Epochs and their envelope secrets, wiped when dropped: what a reseat's
/// gap block carries ([`seal_gap_block`], [`open_gap_block`]).
pub type GapSecrets = crate::secret::Secret<Vec<(u64, [u8; 32])>>;

/// The four bytes a framed Welcome starts with. The first is `0xff`, which a
/// raw MLS message (version `00 01`) never starts with.
pub const WELCOME_FRAME_MAGIC: [u8; 4] = [0xff, 0x50, 0x57, 0x01];

/// The four bytes a framed Welcome that carries a gap block starts with
/// (§The gap block).
pub const WELCOME_FRAME_GAP_MAGIC: [u8; 4] = [0xff, 0x50, 0x57, 0x02];

/// The most epochs a gap block hands back.
pub const WELCOME_GAP_EPOCHS: usize = 32;

/// One epoch in a gap block: the epoch, big-endian, and its secret.
const GAP_ENTRY_BYTES: usize = 8 + 32;

const GAP_NONCE_BYTES: usize = 12;
const GAP_TAG_BYTES: usize = 16;
const GAP_PLAINTEXT_BYTES: usize = 1 + WELCOME_GAP_EPOCHS * GAP_ENTRY_BYTES;

/// A gap block's length, whatever it holds.
pub const WELCOME_GAP_BLOCK_BYTES: usize = GAP_NONCE_BYTES + GAP_PLAINTEXT_BYTES + GAP_TAG_BYTES;

/// The MLS exporter label of a gap block's key. Context: the group id;
/// length: 32.
pub const WELCOME_GAP_EXPORTER_LABEL: &str = "peachy welcome gap v1";

/// The magic and the big-endian length of the Welcome inside.
pub const WELCOME_FRAME_HEADER_BYTES: usize = WELCOME_FRAME_MAGIC.len() + 4;

/// The block a framed Welcome is rounded up to.
pub const WELCOME_FRAME_BLOCK: usize = 256;

/// `welcome` in a frame of `padded_len` bytes, or of the smallest frame that
/// holds it when `padded_len` is less.
pub fn frame_welcome(welcome: &[u8], padded_len: usize) -> Result<Vec<u8>> {
    if welcome.is_empty() {
        return Err(Error::invalid("a Welcome to frame is not empty"));
    }
    let len =
        u32::try_from(welcome.len()).map_err(|_| Error::invalid("a Welcome is under 4 GiB"))?;
    let total = padded_len.max(WELCOME_FRAME_HEADER_BYTES + welcome.len());
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&WELCOME_FRAME_MAGIC);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(welcome);
    out.resize(total, 0);
    Ok(out)
}

/// `welcome` and a sealed `gap_block` ([`seal_gap_block`]) in a version 2
/// frame of `padded_len` bytes, or of the smallest that holds both.
pub fn frame_welcome_with_gap(
    welcome: &[u8],
    gap_block: &[u8],
    padded_len: usize,
) -> Result<Vec<u8>> {
    if gap_block.len() != WELCOME_GAP_BLOCK_BYTES {
        return Err(Error::invalid(
            "a gap block is WELCOME_GAP_BLOCK_BYTES long",
        ));
    }
    let mut out = frame_welcome(welcome, 0)?;
    out[..4].copy_from_slice(&WELCOME_FRAME_GAP_MAGIC);
    out.extend_from_slice(gap_block);
    let total = padded_len.max(out.len());
    out.resize(total, 0);
    Ok(out)
}

/// What a frame holds: the Welcome, and the sealed gap block of a version 2
/// frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnframedWelcome<'a> {
    /// The MLS Welcome.
    pub welcome: &'a [u8],
    /// The sealed gap block, in a version 2 frame (§The gap block).
    pub gap_block: Option<&'a [u8]>,
}

/// The Welcome in `bytes`, the inside of a frame. Anything that is not a
/// frame (a raw Welcome among it), a frame whose length runs past its end,
/// and one whose fill is not all zeros are refused.
pub fn unframe_welcome(bytes: &[u8]) -> Result<&[u8]> {
    unframe_welcome_parts(bytes).map(|parts| parts.welcome)
}

/// [`unframe_welcome`], with the gap block a version 2 frame carries. A
/// version 2 frame too short to hold a whole block is refused.
pub fn unframe_welcome_parts(bytes: &[u8]) -> Result<UnframedWelcome<'_>> {
    let (rest, with_gap) = if let Some(rest) = bytes.strip_prefix(&WELCOME_FRAME_MAGIC[..]) {
        (rest, false)
    } else if let Some(rest) = bytes.strip_prefix(&WELCOME_FRAME_GAP_MAGIC[..]) {
        (rest, true)
    } else {
        return Err(Error::invalid("a Welcome arrives in a frame"));
    };
    let (len, rest) = rest
        .split_first_chunk::<4>()
        .ok_or_else(|| Error::invalid("a Welcome frame ends before its length"))?;
    let len = usize::try_from(u32::from_be_bytes(*len))
        .map_err(|_| Error::invalid("a Welcome frame's length does not fit"))?;
    if len == 0 {
        return Err(Error::invalid("a Welcome frame holds no Welcome"));
    }
    if len > rest.len() {
        return Err(Error::invalid("a Welcome frame's length runs past its end"));
    }
    let (welcome, rest) = rest.split_at(len);
    let (gap_block, fill) = if with_gap {
        let (block, fill) = rest
            .split_at_checked(WELCOME_GAP_BLOCK_BYTES)
            .ok_or_else(|| Error::invalid("a Welcome frame's gap block runs past its end"))?;
        (Some(block), fill)
    } else {
        (None, rest)
    };
    if fill.iter().any(|&b| b != 0) {
        return Err(Error::invalid("a Welcome frame's fill is not zeros"));
    }
    Ok(UnframedWelcome { welcome, gap_block })
}

/// The bytes a refused frame would hand a join as its Welcome: the region its
/// length names when the header is whole and the length fits, and otherwise
/// all of `bytes` (a raw Welcome sent without a frame). Not a Welcome until
/// it parses as one. A join refuses whatever [`unframe_welcome_parts`]
/// refuses, and spends the key package these bytes are sealed to first
/// (`Client::join_from_welcome`).
pub(crate) fn welcome_in_refused_frame(bytes: &[u8]) -> &[u8] {
    let framed = bytes
        .strip_prefix(&WELCOME_FRAME_MAGIC[..])
        .or_else(|| bytes.strip_prefix(&WELCOME_FRAME_GAP_MAGIC[..]));
    let Some(rest) = framed else {
        return bytes;
    };
    rest.split_first_chunk::<4>()
        .and_then(|(len, rest)| {
            let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
            rest.get(..len)
        })
        .unwrap_or(bytes)
}

/// Seal `gap` (epochs and their envelope secrets, at most
/// [`WELCOME_GAP_EPOCHS`]) under `key`, the new epoch's
/// [`WELCOME_GAP_EXPORTER_LABEL`] export: a block of
/// [`WELCOME_GAP_BLOCK_BYTES`] whatever it holds.
pub fn seal_gap_block(key: &[u8], gap: &[(u64, [u8; 32])]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; GAP_NONCE_BYTES];
    getrandom::fill(&mut nonce)
        .map_err(|err| Error::invalid(format!("no randomness for a gap block's nonce: {err}")))?;
    seal_gap_block_with_nonce(key, gap, &nonce)
}

/// [`seal_gap_block`] under a given nonce: for fixtures, never for a send.
pub fn seal_gap_block_with_nonce(
    key: &[u8],
    gap: &[(u64, [u8; 32])],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    let count = u8::try_from(gap.len())
        .ok()
        .filter(|count| usize::from(*count) <= WELCOME_GAP_EPOCHS)
        .ok_or_else(|| Error::invalid("a gap block holds at most WELCOME_GAP_EPOCHS epochs"))?;
    if nonce.len() != GAP_NONCE_BYTES {
        return Err(Error::invalid("a gap block's nonce is 12 bytes"));
    }
    // Sized once and wiped when dropped: it holds every secret in the gap.
    let mut plaintext = zeroize::Zeroizing::new(Vec::with_capacity(GAP_PLAINTEXT_BYTES));
    plaintext.push(count);
    for (epoch, secret) in gap {
        plaintext.extend_from_slice(&epoch.to_be_bytes());
        plaintext.extend_from_slice(secret);
    }
    plaintext.resize(GAP_PLAINTEXT_BYTES, 0);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::invalid("a gap block's key is 32 bytes"))?;
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &plaintext[..],
                aad: WELCOME_GAP_EXPORTER_LABEL.as_bytes(),
            },
        )
        .map_err(|_| Error::invalid("a gap block did not seal"))?;
    let mut block = Vec::with_capacity(WELCOME_GAP_BLOCK_BYTES);
    block.extend_from_slice(nonce);
    block.extend_from_slice(&sealed);
    Ok(block)
}

/// The epochs and secrets in a gap block sealed under `key`. Refused when it
/// does not open, or its count or fill is not what a sealer writes.
pub fn open_gap_block(key: &[u8], block: &[u8]) -> Result<GapSecrets> {
    if block.len() != WELCOME_GAP_BLOCK_BYTES {
        return Err(Error::invalid(
            "a gap block is WELCOME_GAP_BLOCK_BYTES long",
        ));
    }
    let (nonce, sealed) = block.split_at(GAP_NONCE_BYTES);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::invalid("a gap block's key is 32 bytes"))?;
    let plaintext = zeroize::Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: WELCOME_GAP_EXPORTER_LABEL.as_bytes(),
                },
            )
            .map_err(|_| Error::invalid("a gap block does not open under this epoch"))?,
    );
    let (&count, entries) = plaintext
        .split_first()
        .ok_or_else(|| Error::invalid("a gap block is empty"))?;
    let count = usize::from(count);
    if count > WELCOME_GAP_EPOCHS {
        return Err(Error::invalid("a gap block names too many epochs"));
    }
    let (listed, fill) = entries.split_at(count * GAP_ENTRY_BYTES);
    if fill.iter().any(|&b| b != 0) {
        return Err(Error::invalid("a gap block's fill is not zeros"));
    }
    // Sized before the first push, so no reallocation leaves a copy behind.
    let mut gap = GapSecrets::new(Vec::with_capacity(count));
    for entry in listed.as_chunks::<GAP_ENTRY_BYTES>().0 {
        let (epoch, secret) = entry.split_at(8);
        if let (Ok(epoch), Ok(secret)) = (<[u8; 8]>::try_from(epoch), <[u8; 32]>::try_from(secret))
        {
            gap.push((u64::from_be_bytes(epoch), secret));
        }
    }
    Ok(gap)
}

/// A frame's whole length for a Welcome whose largest candidate is
/// `largest_welcome` bytes: the header added, then up to the block.
pub(crate) fn framed_len(largest_welcome: usize) -> usize {
    (WELCOME_FRAME_HEADER_BYTES + largest_welcome).div_ceil(WELCOME_FRAME_BLOCK)
        * WELCOME_FRAME_BLOCK
}

/// [`framed_len`] for a version 2 frame: its gap block counted too.
pub(crate) fn framed_len_with_gap(largest_welcome: usize) -> usize {
    framed_len(largest_welcome + WELCOME_GAP_BLOCK_BYTES)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const RAW: &[u8] = &[0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb];

    #[test]
    fn the_magic_cannot_start_a_raw_welcome() {
        assert_ne!(WELCOME_FRAME_MAGIC[0], RAW[0]);
        assert!(unframe_welcome(RAW).is_err(), "a raw Welcome is refused");
    }

    #[test]
    fn a_frame_round_trips_at_its_target() {
        let framed = frame_welcome(RAW, 256).unwrap();
        assert_eq!(framed.len(), 256);
        assert_eq!(&framed[..4], &WELCOME_FRAME_MAGIC);
        assert_eq!(&framed[4..8], &[0, 0, 0, 6]);
        assert_eq!(unframe_welcome(&framed).unwrap(), RAW);
        // A target below what the Welcome needs gives the smallest frame.
        let tight = frame_welcome(RAW, 0).unwrap();
        assert_eq!(tight.len(), WELCOME_FRAME_HEADER_BYTES + RAW.len());
        assert_eq!(unframe_welcome(&tight).unwrap(), RAW);
    }

    #[test]
    fn a_bad_frame_is_refused() {
        let mut framed = frame_welcome(RAW, 64).unwrap();
        framed[40] = 1;
        assert!(unframe_welcome(&framed).is_err());
        let mut long = frame_welcome(RAW, 64).unwrap();
        long[7] = 0xff;
        assert!(unframe_welcome(&long).is_err());
        assert!(unframe_welcome(&WELCOME_FRAME_MAGIC).is_err());
        assert!(unframe_welcome(&[0xff, 0x50, 0x57, 0x01, 0, 0, 0, 0]).is_err());
        assert!(frame_welcome(&[], 256).is_err());
    }

    #[test]
    fn a_gap_frame_round_trips_and_its_block_opens_only_under_its_key() {
        let key = [7u8; 32];
        let gap = vec![(4u64, [1u8; 32]), (5u64, [2u8; 32])];
        let block = seal_gap_block(&key, &gap).unwrap();
        assert_eq!(block.len(), WELCOME_GAP_BLOCK_BYTES);
        assert_eq!(
            seal_gap_block(&key, &[]).unwrap().len(),
            WELCOME_GAP_BLOCK_BYTES
        );
        let framed = frame_welcome_with_gap(RAW, &block, 2048).unwrap();
        assert_eq!(framed.len(), 2048);
        assert_eq!(&framed[..4], &WELCOME_FRAME_GAP_MAGIC);
        let parts = unframe_welcome_parts(&framed).unwrap();
        assert_eq!(parts.welcome, RAW);
        assert_eq!(parts.gap_block, Some(block.as_slice()));
        assert_eq!(unframe_welcome(&framed).unwrap(), RAW);
        assert_eq!(*open_gap_block(&key, &block).unwrap(), gap);
        assert!(open_gap_block(&[8u8; 32], &block).is_err());
        // Cut short of a whole block: refused.
        let short = &framed[..WELCOME_FRAME_HEADER_BYTES + RAW.len() + 10];
        assert!(unframe_welcome_parts(short).is_err());
        // A version 1 frame carries none.
        let v1 = frame_welcome(RAW, 256).unwrap();
        assert_eq!(unframe_welcome_parts(&v1).unwrap().gap_block, None);
        let too_many = vec![(1u64, [0u8; 32]); WELCOME_GAP_EPOCHS + 1];
        assert!(seal_gap_block(&key, &too_many).is_err());
    }

    #[test]
    fn framed_lengths_are_whole_blocks() {
        assert_eq!(framed_len(1), 256);
        assert_eq!(framed_len(248), 256);
        assert_eq!(framed_len(249), 512);
    }
}
