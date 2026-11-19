// SPDX-License-Identifier: MIT
//! A conversation's handle, and the envelope that hides which conversation a
//! sealed byte belongs to (docs/delivery.md §The wrapped envelope).
//!
//! ## Why an envelope at all
//!
//! An MLS `PrivateMessage` carries its `group_id` and `epoch` in the clear
//! (RFC 9420 §6.3). Once the sender names the recipient devices itself and the
//! server keeps no roster, that header would be the one thing left in a
//! mailbox blob that says which conversation it is — and with the recipient
//! set beside it, who is in it. So every sealed byte a member-rostered
//! conversation sends (message, commit, seat ask, typing frame) is wrapped:
//!
//! ```text
//! 0x02 ‖ nonce (12) ‖ tag (16) ‖ AES-256-GCM(enc_key, nonce, aad = 0x02 ‖ tag,
//!                                            kind ‖ len (4, big-endian) ‖ inner ‖ 0x00…)
//! 0x03 ‖ nonce (12) ‖ tag (16) ‖ AES-256-GCM(enc_key, nonce, aad = 0x03 ‖ tag,
//!                                            kind ‖ len (4, big-endian) ‖ inner ‖ 0x00…)
//! ```
//!
//! - `tag = SHA-256(route_key ‖ nonce)[..16]`
//! - version 2, keyed by the GROUP ID:
//!   `enc_key = SHA-256("peachy envelope v1" ‖ group_id)`,
//!   `route_key = SHA-256("peachy route v1" ‖ group_id)`
//! - version 3, keyed by the EPOCH: with
//!   `epoch_secret = MLS-Exporter("peachy envelope epoch v1", group_id, 32)`
//!   at the epoch the sender is in,
//!   `enc_key = SHA-256("peachy epoch envelope v1" ‖ epoch_secret)`,
//!   `route_key = SHA-256("peachy epoch route v1" ‖ epoch_secret)`
//! - both: the zeros pad the whole envelope to
//!   [`padded_envelope_len`]: at least [`ENVELOPE_MIN_BYTES`], and above that
//!   a bucket that depends on the length alone (Padmé), so a length says how
//!   big an envelope is and never what kind it is.
//!
//! ## Keyed by the epoch, not the group id
//!
//! Anybody who ever knew the group id can compute the version 2 keys for as
//! long as the group lives: a removed member, and anybody who held a
//! group link. With them, every later envelope of the group is recognizable
//! and its outer layer opens, though no content does. Version 3 keys come
//! from the MLS exporter of one epoch, so they change with every commit, and
//! a member removed by a commit never holds the keys of the epoch after it.
//! A receiver keeps the keys of the current epoch and of
//! [`crate::group::ENVELOPE_PAST_EPOCHS`] past ones, for a message sealed
//! just before a commit it has already applied and for a reseat to hand back
//! to a device that missed them ([`crate::welcome_frame`] §The gap block).
//!
//! ## Which version is sent
//!
//! A device seals every envelope of a group it holds by the epoch, as
//! version 3 ([`crate::group::Client::seal_envelope`]). A seat ask and a
//! link preview are keyed by the group id, as version 2: the device that
//! sends a seat ask holds no current epoch of the group, and a preview is for
//! link holders, who hold none either. Both versions are read; any other
//! version byte is refused.
//!
//! The group id is known only to members (the server sees its HANDLE, a hash
//! under a third label), so only a member can compute any of the keys. A
//! receiver finds the conversation by computing the tag for each group it
//! holds, and for version 3 each epoch it keeps, and opens only the one that
//! matches. The nonce is fresh per envelope, so two envelopes of one
//! conversation share no byte the server could group them by.
//!
//! A Welcome is never wrapped: it carries no group id in the clear, and its
//! recipient holds no group to route it with yet.
//!
//! ## Kinds
//!
//! The first plaintext byte says what the inner bytes are. It is under the
//! envelope's key, so the server, which sees only `MAILBOX_KIND_MLS` or
//! `MAILBOX_KIND_COMMIT` at the door, cannot read the kind from an envelope's
//! bytes, nor from its LENGTH: both versions pad every kind by one rule, so
//! a length says how big an envelope is and never which kind it is. Every
//! MLS application message is padded inside MLS to 256-byte blocks, and a
//! call signal on the MLS lane is as long as a hinted message of its block
//! ([`crate::call::CALL_LANE_AAD`]). The kinds:
//! [`ENVELOPE_KIND_MESSAGE`], [`ENVELOPE_KIND_COMMIT`],
//! [`ENVELOPE_KIND_SEAT_ASK`], [`ENVELOPE_KIND_TYPING`],
//! [`ENVELOPE_KIND_LINK_PREVIEW`], [`ENVELOPE_KIND_CALL`].
//!
//! `mls/fixtures/rosters.json` pins the bytes, replayed through the fixture
//! door (`kind: "roster"`) in every binding.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

/// Version 2: `kind ‖ len ‖ inner ‖ zeros`, padded to [`padded_envelope_len`],
/// keyed by the group id: a seat ask and a link preview.
pub const ENVELOPE_VERSION_PADDED: u8 = 2;
/// Version 3: the version 2 layout, keyed by the epoch
/// ([`EPOCH_ENVELOPE_EXPORTER_LABEL`]): everything else
/// ([`crate::group::Client::seal_envelope`]).
pub const ENVELOPE_VERSION_EPOCH: u8 = 3;

/// The MLS exporter label of a group's epoch envelope secret, what a version
/// 3 envelope's keys derive from. Context: the group id; length: 32.
pub const EPOCH_ENVELOPE_EXPORTER_LABEL: &str = "peachy envelope epoch v1";

/// Whether `version` is keyed by the group id (2) rather than the epoch.
fn version_is_static(version: u8) -> bool {
    version == ENVELOPE_VERSION_PADDED
}

/// Whether `envelope` says it is keyed by an epoch (version 3). One that
/// opens for no group here was sealed at an epoch this device does not hold,
/// which is how a copy that forked or fell behind looks from the inside.
pub fn envelope_is_epoch_keyed(envelope: &[u8]) -> bool {
    envelope.len() >= HEADER_BYTES && envelope[0] == ENVELOPE_VERSION_EPOCH
}

/// An MLS application message or proposal.
pub const ENVELOPE_KIND_MESSAGE: u8 = 1;
/// A commit accepted by the arbiter.
pub const ENVELOPE_KIND_COMMIT: u8 = 2;
/// A device with no leaf asking to be seated: the inner bytes are the
/// client's JSON `{"d":<device id>,"a":<actor id>}`.
pub const ENVELOPE_KIND_SEAT_ASK: u8 = 3;
/// A typing frame (docs/sealed-messages.md §Typing inside the group).
pub const ENVELOPE_KIND_TYPING: u8 = 4;
/// A group link's PREVIEW (docs/sealed-messages.md §The preview): the group's
/// name, photo and member count, sealed under the group id so that only a
/// holder of the link can read it. Published at the head by a member's
/// device; never placed in a mailbox.
pub const ENVELOPE_KIND_LINK_PREVIEW: u8 = 5;
/// Call signaling (docs/calls.md §Signaling): the inner bytes are a
/// lane byte and then either an MLS application message or an
/// exporter-keyed live frame ([`crate::call::frame`]). The server sees an
/// ordinary mailbox envelope and does not learn it is a call.
pub const ENVELOPE_KIND_CALL: u8 = 6;

/// The kind the delivery service put on a mailbox entry whose payload is an
/// envelope of anything but a commit (`MailboxKind.MAILBOX_KIND_MLS`).
pub const MAILBOX_KIND_MLS: u32 = 1;
/// The kind the delivery service put on a mailbox entry the arbiter ordered:
/// a commit (`MailboxKind.MAILBOX_KIND_COMMIT`).
pub const MAILBOX_KIND_COMMIT: u32 = 5;

/// Which path an opened mailbox entry takes ([`envelope_door`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeDoor {
    /// Acknowledged unread.
    Drop = 0,
    /// [`crate::Client::process_message`].
    Message = 1,
    /// [`crate::Client::process_commit`].
    Commit = 2,
    /// A seat ask ([`ENVELOPE_KIND_SEAT_ASK`]).
    SeatAsk = 3,
    /// Call signaling ([`ENVELOPE_KIND_CALL`]).
    Call = 4,
}

/// WHICH PATH AN OPENED MAILBOX ENTRY TAKES, from the kind the delivery
/// service put on the entry and the kind sealed inside it.
///
/// A commit is taken ONLY from a [`MAILBOX_KIND_COMMIT`] entry, one the
/// arbiter ordered (one commit per epoch). A commit wrapped into an MLS entry
/// skipped the arbiter, so a member could hand different commits for one
/// epoch to different devices; it is dropped. A COMMIT entry carries only a
/// commit. Typing frames, link previews and unknown kinds are dropped here:
/// a typing frame has its own reader, and a link preview is never placed in a
/// mailbox. Choosing the door from the envelope kind alone loses this check,
/// which is why [`crate::Client::process_mailbox_entry`] takes both kinds.
pub fn envelope_door(mailbox_kind: u32, envelope_kind: u8) -> EnvelopeDoor {
    match (mailbox_kind, envelope_kind) {
        (MAILBOX_KIND_COMMIT, ENVELOPE_KIND_COMMIT) => EnvelopeDoor::Commit,
        (MAILBOX_KIND_MLS, ENVELOPE_KIND_MESSAGE) => EnvelopeDoor::Message,
        (MAILBOX_KIND_MLS, ENVELOPE_KIND_SEAT_ASK) => EnvelopeDoor::SeatAsk,
        (MAILBOX_KIND_MLS, ENVELOPE_KIND_CALL) => EnvelopeDoor::Call,
        _ => EnvelopeDoor::Drop,
    }
}

const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = 1 + NONCE_BYTES + TAG_BYTES;
const AEAD_TAG_BYTES: usize = 16;
/// The kind byte and the inner length ahead of the inner bytes.
const PREFIX_BYTES: usize = 1 + 4;
/// Everything an envelope adds to its inner bytes before padding.
const OVERHEAD_BYTES: usize = HEADER_BYTES + AEAD_TAG_BYTES + PREFIX_BYTES;

/// The smallest envelope. Every short envelope is exactly this long: a
/// receipt, a reaction, a short message, a seat ask, a typing frame and a
/// call frame are one size on the wire.
pub const ENVELOPE_MIN_BYTES: usize = 512;

/// Padmé (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and
/// Communication with PURBs", PETS 2019): `len` rounded up so that only its
/// top `floor(log2(floor(log2 len))) + 1` bits may be non-zero. At most
/// O(log log len) bits of the length survive, for at most 12% overhead.
fn padme(len: usize) -> usize {
    if len < 2 {
        return len;
    }
    let e = usize::BITS - 1 - len.leading_zeros();
    let s = u32::BITS - e.leading_zeros();
    let low = e.saturating_sub(s);
    let mask = (1usize << low) - 1;
    (len + mask) & !mask
}

/// The length of the envelope that wraps `inner_len` inner bytes, whatever
/// its kind: `max(ENVELOPE_MIN_BYTES, padme(overhead + inner_len))`.
pub fn padded_envelope_len(inner_len: usize) -> usize {
    padme(OVERHEAD_BYTES + inner_len).max(ENVELOPE_MIN_BYTES)
}

pub(crate) const HANDLE_LABEL: &[u8] = b"peachy handle v1";
pub(crate) const ENVELOPE_LABEL: &[u8] = b"peachy envelope v1";
pub(crate) const ROUTE_LABEL: &[u8] = b"peachy route v1";
pub(crate) const EPOCH_ENVELOPE_LABEL: &[u8] = b"peachy epoch envelope v1";
pub(crate) const EPOCH_ROUTE_LABEL: &[u8] = b"peachy epoch route v1";

fn labelled(label: &[u8], input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(input);
    h.finalize().into()
}

/// A conversation's HANDLE: `SHA-256("peachy handle v1" ‖ group id)`. What
/// the arbiter keys a conversation by; the group id itself never reaches the
/// server.
pub fn group_handle(group_id: &[u8]) -> Result<[u8; 32]> {
    if group_id.is_empty() {
        return Err(Error::invalid("a group id must not be empty"));
    }
    Ok(labelled(HANDLE_LABEL, group_id))
}

/// The two keys of one envelope: the AEAD key and the route key its tag is
/// made with.
struct Keys {
    enc: [u8; 32],
    route: [u8; 32],
}

/// Both keys are wiped when the envelope is sealed or opened: a version 3
/// pair is as good as the epoch's envelope secret for its envelopes.
impl Drop for Keys {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.enc);
        zeroize::Zeroize::zeroize(&mut self.route);
    }
}

impl Keys {
    /// Versions 1 and 2: from the group id.
    fn of_group(group_id: &[u8]) -> Result<Self> {
        if group_id.is_empty() {
            return Err(Error::invalid("a group id must not be empty"));
        }
        Ok(Self {
            enc: labelled(ENVELOPE_LABEL, group_id),
            route: labelled(ROUTE_LABEL, group_id),
        })
    }

    /// Version 3: from one epoch's envelope secret.
    fn of_epoch(epoch_secret: &[u8]) -> Result<Self> {
        if epoch_secret.len() != 32 {
            return Err(Error::invalid("an epoch envelope secret is 32 bytes"));
        }
        Ok(Self {
            enc: labelled(EPOCH_ENVELOPE_LABEL, epoch_secret),
            route: labelled(EPOCH_ROUTE_LABEL, epoch_secret),
        })
    }

    fn tag(&self, nonce: &[u8]) -> [u8; TAG_BYTES] {
        let mut h = Sha256::new();
        h.update(self.route);
        h.update(nonce);
        let full: [u8; 32] = h.finalize().into();
        let mut tag = [0u8; TAG_BYTES];
        tag.copy_from_slice(&full[..TAG_BYTES]);
        tag
    }

    fn cipher(&self) -> Result<Aes256Gcm> {
        Aes256Gcm::new_from_slice(&self.enc)
            .map_err(|_| Error::invalid("an AES-256 key must be 32 bytes"))
    }

    /// Whether `envelope`'s tag is this key's, by the tag alone. The
    /// comparison takes the same time wherever the tags differ.
    fn routes(&self, envelope: &[u8]) -> bool {
        if envelope.len() < HEADER_BYTES {
            return false;
        }
        let nonce = &envelope[1..1 + NONCE_BYTES];
        self.tag(nonce)[..]
            .ct_eq(&envelope[1 + NONCE_BYTES..HEADER_BYTES])
            .into()
    }
}

fn check_kind(kind: u8) -> Result<()> {
    if (ENVELOPE_KIND_MESSAGE..=ENVELOPE_KIND_CALL).contains(&kind) {
        Ok(())
    } else {
        Err(Error::invalid(format!("{kind} is not an envelope kind")))
    }
}

fn fresh_nonce() -> Result<[u8; NONCE_BYTES]> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce)
        .map_err(|err| Error::invalid(format!("no randomness for an envelope nonce: {err}")))?;
    Ok(nonce)
}

/// Wrap `inner` for `group_id` under a fresh random nonce, as version 2,
/// keyed by the group id: a seat ask ([`ENVELOPE_KIND_SEAT_ASK`]) or a link
/// preview ([`ENVELOPE_KIND_LINK_PREVIEW`]), and nothing else. Whoever opens
/// those holds no epoch of the group.
///
/// Every other kind is refused ([`Error::InvalidArgument`]): a message,
/// commit, typing frame or call signal goes through
/// [`crate::group::Client::seal_envelope`], which seals by the epoch. In the
/// group-id form it would open for a removed member and anyone holding a
/// link to the group, and would mark the client that sent it apart from
/// every other.
pub fn seal_envelope(group_id: &[u8], kind: u8, inner: &[u8]) -> Result<Vec<u8>> {
    if kind != ENVELOPE_KIND_SEAT_ASK && kind != ENVELOPE_KIND_LINK_PREVIEW {
        check_kind(kind)?;
        return Err(Error::invalid(format!(
            "kind {kind} is sealed by the client holding the group, not by the group id alone"
        )));
    }
    seal_group_id_envelope(group_id, kind, inner)
}

/// [`seal_envelope`] for any kind: the group-id form
/// [`crate::group::Client::seal_envelope`] takes for a seat ask or a link
/// preview (any other kind is sealed under an epoch of a held group, or
/// refused). Public only to the crate's own tests
/// and the fixture build, as the fixture's other sealing doors are.
#[cfg(any(test, feature = "fixture"))]
pub fn seal_group_id_envelope(group_id: &[u8], kind: u8, inner: &[u8]) -> Result<Vec<u8>> {
    seal_with_nonce(group_id, kind, inner, &fresh_nonce()?)
}

#[cfg(not(any(test, feature = "fixture")))]
pub(crate) fn seal_group_id_envelope(group_id: &[u8], kind: u8, inner: &[u8]) -> Result<Vec<u8>> {
    seal_with_nonce(group_id, kind, inner, &fresh_nonce()?)
}

/// Wrap `inner` as a version 3 envelope under one epoch's envelope secret
/// (`MLS-Exporter("peachy envelope epoch v1", group id, 32)` at the sender's
/// epoch), under a fresh random nonce.
pub fn seal_epoch_envelope(epoch_secret: &[u8], kind: u8, inner: &[u8]) -> Result<Vec<u8>> {
    seal_keyed(
        &Keys::of_epoch(epoch_secret)?,
        kind,
        inner,
        &fresh_nonce()?,
        ENVELOPE_VERSION_EPOCH,
    )
}

/// [`seal_envelope`] with the nonce given — the fixture's deterministic door,
/// and nothing a client should call. A nonce used twice under one group's key
/// is AES-GCM's one fatal misuse (the two plaintexts' XOR, and a forgery key)
/// and repeats the route tag, so this is compiled only for the golden
/// fixture, the fuzz targets and the crate's own tests, behind the same gate
/// as the account store's fixed-nonce sealer; no binding can reach it.
#[cfg(any(test, feature = "fixture"))]
pub fn seal_envelope_with_nonce(
    group_id: &[u8],
    kind: u8,
    inner: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    seal_with_nonce(group_id, kind, inner, nonce)
}

/// [`seal_epoch_envelope`] with the nonce given, behind the same gate as
/// [`seal_envelope_with_nonce`].
#[cfg(any(test, feature = "fixture"))]
pub fn seal_epoch_envelope_with_nonce(
    epoch_secret: &[u8],
    kind: u8,
    inner: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    seal_keyed(
        &Keys::of_epoch(epoch_secret)?,
        kind,
        inner,
        nonce,
        ENVELOPE_VERSION_EPOCH,
    )
}

fn seal_with_nonce(group_id: &[u8], kind: u8, inner: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    seal_keyed(
        &Keys::of_group(group_id)?,
        kind,
        inner,
        nonce,
        ENVELOPE_VERSION_PADDED,
    )
}

fn seal_keyed(keys: &Keys, kind: u8, inner: &[u8], nonce: &[u8], version: u8) -> Result<Vec<u8>> {
    check_kind(kind)?;
    if nonce.len() != NONCE_BYTES {
        return Err(Error::invalid("an envelope nonce is 12 bytes"));
    }
    let tag = keys.tag(nonce);
    let mut aad = Vec::with_capacity(1 + TAG_BYTES);
    aad.push(version);
    aad.extend_from_slice(&tag);
    // The kind and inner bytes, padded: wiped once sealed (a seat ask's or a
    // link preview's inner bytes are what it says). Each is sized before its
    // first byte, so no growth leaves a copy behind.
    let inner_len = u32::try_from(inner.len())
        .map_err(|_| Error::invalid("an envelope's inner bytes are under 4 GiB"))?;
    let total = padded_envelope_len(inner.len());
    let plaintext = zeroize::Zeroizing::new({
        let mut plaintext = Vec::with_capacity(total - HEADER_BYTES - AEAD_TAG_BYTES);
        plaintext.push(kind);
        plaintext.extend_from_slice(&inner_len.to_be_bytes());
        plaintext.extend_from_slice(inner);
        plaintext.resize(total - HEADER_BYTES - AEAD_TAG_BYTES, 0);
        plaintext
    });
    let sealed = keys
        .cipher()?
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| Error::invalid("the envelope did not seal"))?;
    let mut out = Vec::with_capacity(HEADER_BYTES + sealed.len());
    out.push(version);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Whether `envelope` was wrapped for `group_id` under its group-id keys
/// (version 2) — the tag comparison alone, no decryption. The
/// comparison takes the same time wherever the tags differ. A version 3
/// envelope is never for a group id: only an epoch's secret routes it
/// ([`epoch_envelope_is_for`]).
pub fn envelope_is_for(group_id: &[u8], envelope: &[u8]) -> bool {
    if envelope.len() < HEADER_BYTES || !version_is_static(envelope[0]) {
        return false;
    }
    Keys::of_group(group_id).is_ok_and(|keys| keys.routes(envelope))
}

/// Whether `envelope` is a version 3 envelope sealed under `epoch_secret`:
/// the tag comparison alone, as [`envelope_is_for`].
pub fn epoch_envelope_is_for(epoch_secret: &[u8], envelope: &[u8]) -> bool {
    if !envelope_is_epoch_keyed(envelope) {
        return false;
    }
    Keys::of_epoch(epoch_secret).is_ok_and(|keys| keys.routes(envelope))
}

/// An opened envelope. `inner` is the caller's to wipe; its `Debug` gives
/// the length alone.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenedEnvelope {
    pub group_id: Vec<u8>,
    pub kind: u8,
    pub inner: Vec<u8>,
}

impl std::fmt::Debug for OpenedEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedEnvelope")
            .field("group_id", &self.group_id)
            .field("kind", &self.kind)
            .field("inner_len", &self.inner.len())
            .finish()
    }
}

/// Open `envelope` as `group_id`'s, under its group-id keys (version 2).
/// `Err` when the tag or the AEAD does not match, the kind is unknown,
/// or it is a version 3 envelope, which only an epoch's secret opens
/// ([`open_epoch_envelope`]).
pub fn open_envelope_for(group_id: &[u8], envelope: &[u8]) -> Result<OpenedEnvelope> {
    if !envelope_is_for(group_id, envelope) {
        return Err(Error::invalid("that envelope is not for this group"));
    }
    let (kind, mut inner) = open_keyed(&Keys::of_group(group_id)?, envelope)?;
    Ok(OpenedEnvelope {
        group_id: group_id.to_vec(),
        kind,
        inner: std::mem::take(&mut *inner),
    })
}

/// Open a version 3 `envelope` under `epoch_secret`: its kind and inner
/// bytes, wiped when dropped. `Err` when it is not version 3, the tag or the
/// AEAD does not match, or the kind is unknown.
pub fn open_epoch_envelope(
    epoch_secret: &[u8],
    envelope: &[u8],
) -> Result<(u8, zeroize::Zeroizing<Vec<u8>>)> {
    if !epoch_envelope_is_for(epoch_secret, envelope) {
        return Err(Error::invalid("that envelope is not for this epoch"));
    }
    open_keyed(&Keys::of_epoch(epoch_secret)?, envelope)
}

/// The AEAD and the layout, once the tag has matched `keys`: the kind and the
/// inner bytes, wiped when dropped.
fn open_keyed(keys: &Keys, envelope: &[u8]) -> Result<(u8, zeroize::Zeroizing<Vec<u8>>)> {
    if envelope.len() < HEADER_BYTES {
        return Err(Error::invalid("shorter than an envelope"));
    }
    let nonce = &envelope[1..1 + NONCE_BYTES];
    let aad = [&envelope[..1], &envelope[1 + NONCE_BYTES..HEADER_BYTES]].concat();
    // The AEAD's output, the kind and inner bytes with any padding: wiped
    // once the inner bytes are copied out of it.
    let plaintext = zeroize::Zeroizing::new(
        keys.cipher()?
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &envelope[HEADER_BYTES..],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::invalid("the envelope did not open"))?,
    );
    if plaintext.len() < PREFIX_BYTES {
        return Err(Error::invalid("an envelope carries a kind and a length"));
    }
    let kind = plaintext[0];
    check_kind(kind)?;
    let mut len = [0u8; 4];
    len.copy_from_slice(&plaintext[1..PREFIX_BYTES]);
    let len = u32::from_be_bytes(len) as usize;
    let rest = &plaintext[PREFIX_BYTES..];
    if len > rest.len() {
        return Err(Error::invalid("an envelope's length runs past its end"));
    }
    let (inner, padding) = rest.split_at(len);
    if padding.iter().any(|&b| b != 0) {
        return Err(Error::invalid("an envelope's padding is not zeros"));
    }
    Ok((kind, zeroize::Zeroizing::new(inner.to_vec())))
}

/// Open `envelope` against every group in `group_ids`, under their group-id
/// keys, returning the first whose tag matches and whose AEAD opens.
/// `Ok(None)` when none does, and for every version 3 envelope.
pub fn open_envelope_among<'a>(
    group_ids: impl IntoIterator<Item = &'a [u8]>,
    envelope: &[u8],
) -> Result<Option<OpenedEnvelope>> {
    if envelope.len() < HEADER_BYTES || !version_is_static(envelope[0]) {
        return Ok(None);
    }
    for gid in group_ids {
        if envelope_is_for(gid, envelope) {
            if let Ok(opened) = open_envelope_for(gid, envelope) {
                return Ok(Some(opened));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_routes() {
        let a = b"11111111-1111-4111-8111-111111111111";
        let b = b"22222222-2222-4222-8222-222222222222";
        let sealed = seal_group_id_envelope(a, ENVELOPE_KIND_MESSAGE, b"hello").unwrap();
        assert!(envelope_is_for(a, &sealed));
        assert!(!envelope_is_for(b, &sealed));
        let opened = open_envelope_among([&b[..], &a[..]], &sealed)
            .unwrap()
            .unwrap();
        assert_eq!(opened.group_id, a.to_vec());
        assert_eq!(opened.kind, ENVELOPE_KIND_MESSAGE);
        assert_eq!(opened.inner, b"hello".to_vec());
        assert!(open_envelope_among([&b[..]], &sealed).unwrap().is_none());
    }

    #[test]
    fn two_envelopes_of_one_group_share_no_header() {
        let a = b"11111111-1111-4111-8111-111111111111";
        let x = seal_group_id_envelope(a, ENVELOPE_KIND_MESSAGE, b"x").unwrap();
        let y = seal_group_id_envelope(a, ENVELOPE_KIND_MESSAGE, b"x").unwrap();
        assert_ne!(x[1..HEADER_BYTES], y[1..HEADER_BYTES]);
    }

    #[test]
    fn the_group_id_is_not_in_the_bytes() {
        let a = b"11111111-1111-4111-8111-111111111111";
        let sealed = seal_group_id_envelope(a, ENVELOPE_KIND_COMMIT, a).unwrap();
        assert!(!sealed.windows(a.len()).any(|w| w == a));
        let handle = group_handle(a).unwrap();
        assert!(!sealed.windows(8).any(|w| w == &handle[..8]));
    }

    #[test]
    fn a_tampered_envelope_does_not_open() {
        let a = b"11111111-1111-4111-8111-111111111111";
        let mut sealed = seal_group_id_envelope(a, ENVELOPE_KIND_MESSAGE, b"hello").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open_envelope_for(a, &sealed).is_err());
        assert!(open_envelope_among([&a[..]], &sealed).unwrap().is_none());
    }

    #[test]
    fn padme_keeps_few_bits() {
        assert_eq!(padme(0), 0);
        assert_eq!(padme(1), 1);
        assert_eq!(padme(512), 512);
        assert_eq!(padme(513), 544);
        assert_eq!(padme(643), 672);
        assert_eq!(padme(131_072 + 50), 131_072 + 4096);
        assert_eq!(padded_envelope_len(0), ENVELOPE_MIN_BYTES);
        assert_eq!(
            padded_envelope_len(ENVELOPE_MIN_BYTES - OVERHEAD_BYTES),
            ENVELOPE_MIN_BYTES
        );
        assert_eq!(
            padded_envelope_len(ENVELOPE_MIN_BYTES - OVERHEAD_BYTES + 1),
            544
        );
    }

    #[test]
    fn version_two_is_sent_padded() {
        let a = b"11111111-1111-4111-8111-111111111111";
        let sent = seal_group_id_envelope(a, ENVELOPE_KIND_MESSAGE, b"hello").unwrap();
        assert_eq!(sent[0], ENVELOPE_VERSION_PADDED);
        assert_eq!(sent.len(), ENVELOPE_MIN_BYTES);
        let opened = open_envelope_among([&a[..]], &sent).unwrap().unwrap();
        assert_eq!(opened.kind, ENVELOPE_KIND_MESSAGE);
        assert_eq!(opened.inner, b"hello".to_vec());
    }

    #[test]
    fn a_version_byte_flipped_or_unknown_does_not_open() {
        let a = b"11111111-1111-4111-8111-111111111111";
        for to in [1, 3, 4] {
            let mut sealed = seal_group_id_envelope(a, ENVELOPE_KIND_MESSAGE, b"hello").unwrap();
            sealed[0] = to;
            assert!(open_envelope_among([&a[..]], &sealed).unwrap().is_none());
            assert!(open_envelope_for(a, &sealed).is_err());
        }
    }

    #[test]
    fn unknown_kinds_are_refused() {
        let a = b"g";
        assert!(seal_group_id_envelope(a, 0, b"").is_err());
        assert!(seal_group_id_envelope(a, ENVELOPE_KIND_CALL, b"").is_ok());
        assert!(seal_group_id_envelope(a, 7, b"").is_err());
        // The clientless door: a seat ask and a link preview, nothing else.
        for kind in [ENVELOPE_KIND_SEAT_ASK, ENVELOPE_KIND_LINK_PREVIEW] {
            let sealed = seal_envelope(a, kind, b"ask").unwrap();
            assert_eq!(sealed[0], ENVELOPE_VERSION_PADDED);
            assert_eq!(open_envelope_for(a, &sealed).unwrap().kind, kind);
        }
        for kind in [
            0,
            ENVELOPE_KIND_MESSAGE,
            ENVELOPE_KIND_COMMIT,
            ENVELOPE_KIND_TYPING,
            ENVELOPE_KIND_CALL,
            7,
        ] {
            assert!(
                matches!(seal_envelope(a, kind, b""), Err(Error::InvalidArgument(_))),
                "kind {kind}"
            );
        }
    }

    #[test]
    fn an_epoch_envelope_opens_only_under_its_epoch() {
        let e1 = [1u8; 32];
        let e2 = [2u8; 32];
        let sealed = seal_epoch_envelope(&e1, ENVELOPE_KIND_MESSAGE, b"hello").unwrap();
        assert_eq!(sealed[0], ENVELOPE_VERSION_EPOCH);
        assert_eq!(sealed.len(), ENVELOPE_MIN_BYTES);
        assert!(envelope_is_epoch_keyed(&sealed));
        assert!(epoch_envelope_is_for(&e1, &sealed));
        assert!(!epoch_envelope_is_for(&e2, &sealed));
        let (kind, inner) = open_epoch_envelope(&e1, &sealed).unwrap();
        assert_eq!(
            (kind, inner.to_vec()),
            (ENVELOPE_KIND_MESSAGE, b"hello".to_vec())
        );
        assert!(open_epoch_envelope(&e2, &sealed).is_err());
        assert!(seal_epoch_envelope(&[1u8; 31], ENVELOPE_KIND_MESSAGE, b"").is_err());
    }

    #[test]
    fn the_group_id_neither_routes_nor_opens_an_epoch_envelope() {
        // The point of version 3: holding the group id (a removed member, a
        // link holder) recognizes and opens nothing sealed by the epoch,
        // even where the epoch secret were the group id's bytes.
        let a = [7u8; 32];
        let sealed = seal_epoch_envelope(&a, ENVELOPE_KIND_MESSAGE, b"hello").unwrap();
        assert!(!envelope_is_for(&a, &sealed));
        assert!(open_envelope_for(&a, &sealed).is_err());
        assert!(open_envelope_among([&a[..]], &sealed).unwrap().is_none());
        // And a group-id envelope is not an epoch one.
        let old = seal_group_id_envelope(&a, ENVELOPE_KIND_MESSAGE, b"hi").unwrap();
        assert!(!envelope_is_epoch_keyed(&old));
        assert!(!epoch_envelope_is_for(&a, &old));
        assert!(open_epoch_envelope(&a, &old).is_err());
    }

    #[test]
    fn an_epoch_envelope_relabelled_does_not_open() {
        let e = [3u8; 32];
        let mut sealed = seal_epoch_envelope(&e, ENVELOPE_KIND_TYPING, b"t").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open_epoch_envelope(&e, &sealed).is_err());
        let sealed = seal_epoch_envelope(&e, ENVELOPE_KIND_TYPING, b"t").unwrap();
        let mut as_two = sealed.clone();
        as_two[0] = ENVELOPE_VERSION_PADDED;
        assert!(open_epoch_envelope(&e, &as_two).is_err());
    }
}
