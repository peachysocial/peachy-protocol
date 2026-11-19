// SPDX-License-Identifier: MIT
//! The steward key, the commit MAC, the sealed stamp, the veto frame and the
//! group hold (docs/delivery.md §The sealed stamp). No build writes a
//! steward key, and none acts on these ([`STEWARD_WRITES`], [`STEWARD_READS`]).
//!
//! ## The pieces
//!
//! - **The commit MAC.** The committer sends
//!   `HMAC(exporter_E("peachy commit mac", group_id), S ‖ BE64(E) ‖ SHA-256(entry))`
//!   beside its commit. Only a member of epoch E holds the key, so a valid MAC
//!   proves a member named `S`.
//! - **The sealed stamp.** The server seals `S ‖ steward_pub ‖ mac` under a key
//!   derived from the epoch's send key and hands it out with the commit. A
//!   receiver compares `S` with the verifier the commit really produces.
//! - **The steward key.** One Ed25519 key per group, whose public half the
//!   server holds from the group's founding, and whose seed the admins hold in
//!   the meta (`stw`). It signs a repair (put the head's verifier right) and a
//!   veto (roll the head back to the epoch a commit was built in, and place an
//!   empty replacement there).
//! - **The veto frame**, which a vetoing replacement commit is wrapped in, so
//!   every receiver can check the steward signed it.
//! - **The group hold**: a device that cannot apply the commit at its epoch
//!   in a group with a steward key waits, rather than strand or rejoin, while
//!   an admin repairs or vetoes.
//!
//! ## The frames nest
//!
//! ```text
//! envelope (kind 2)
//!   → optional veto frame:    ff 56 54 01 ‖ BE16(len) ‖ signed veto (len) ‖ inner
//!     → optional carried frame: ff 4c 43 01 … (crate::carried_commit)
//!       → raw commit            00 01 …
//! signed veto = 0x01 ‖ handle (32) ‖ BE64(E) ‖ vetoed next (32) ‖ replacement next (32) ‖ sig (64)
//! ```
//!
//! Each frame appears at most once. [`crate::carried_commit::split_carried`]
//! strips the veto frame first, so the commit door, `Client::commit_strands`
//! and [`crate::hint::peek_message`] all read it.
//!
//! The stamp and the MAC are checked and only alert
//! (`Client::take_commit_check`); an enrolled group behaves as one never
//! enrolled.
//!
//! A mix of builds that honor a veto and builds that do not cannot fork a
//! group. A device that does not honor one takes the vetoed commit if it is
//! served, lands on a branch the head is not on, and finds that out the way
//! a device in an unenrolled group always does: a veto frame of an earlier
//! epoch asks it to read the head (`VetoVerdict::CheckHead`), the head check
//! reads it forked, and it rejoins onto the head. One that honors skips
//! straight to the replacement. Both end on the server's one head; the
//! difference is a rejoin, never two live branches.
//!
//! `mls/fixtures/steward.json` pins every byte format here, replayed through
//! the fixture door (`kind: "steward"`) in every binding.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// The four bytes a veto frame starts with. The first is `0xff`, which a raw
/// MLS message (version `00 01`) never starts with; the second tells it from
/// a carried frame ([`crate::carried_commit::CARRIED_COMMIT_MAGIC`]).
pub const VETO_FRAME_MAGIC: [u8; 4] = [0xff, 0x56, 0x54, 0x01];

/// The signed veto's version byte.
pub const SIGNED_VETO_VERSION: u8 = 1;

/// A signed veto's length: version, handle, epoch, two verifiers, signature.
pub const SIGNED_VETO_BYTES: usize = 1 + 32 + 8 + 32 + 32 + 64;

/// The MLS exporter label of the commit MAC's key. Context: the group id;
/// length: 32.
pub const COMMIT_MAC_LABEL: &str = "peachy commit mac";

/// HKDF-SHA256 info, over the epoch's send key, of the sealed stamp's key.
pub const COMMIT_STAMP_INFO: &str = "peachy commit stamp v1";

/// HKDF-SHA256 info, over the epoch's send key, of the head log's copy key.
pub const COMMIT_LOG_INFO: &str = "peachy commit log v1";

/// What the steward key signs to repair a head.
pub const STEWARD_REPAIR_DOMAIN: &str = "peachy steward repair v1";

/// What the steward key signs to veto a commit.
pub const STEWARD_VETO_DOMAIN: &str = "peachy steward veto v1";

/// What the steward key signs to hand a handle to its next key.
pub const STEWARD_CHANGE_DOMAIN: &str = "peachy steward change v1";

/// The sealed stamp's and the log copy's version byte.
pub const SEALED_VERSION: u8 = 1;

/// What sealing adds to a stamp or a log copy: the version byte, the
/// 12-byte nonce and the 16-byte tag.
pub const SEALED_OVERHEAD: usize = 1 + 12 + 16;

/// A sealed stamp's length: version, nonce, 96 bytes sealed, tag.
pub const STAMP_BYTES: usize = 96 + SEALED_OVERHEAD;

/// The repair notice's lane tag.
pub const REPAIR_NOTICE_KIND: &str = "repair";

/// Whether this build WRITES a steward key, a MAC, a repair or a veto. False:
/// it reads every one of them, and writes none, so no group's meta names a
/// key and the hold never engages.
pub const STEWARD_WRITES: bool = false;

/// Whether this build HONORS a steward: holds an enrolled group
/// (`Client::enter_hold`, `Client::group_hold`) and lets a veto skip a
/// commit or send a copy to rejoin (`Client::judge_veto`). False: the
/// reading side is kept, and acts on nothing, so a group behaves as one never
/// enrolled.
pub const STEWARD_READS: bool = false;

/// The longest a group stays held. One hour.
pub const HOLD_CAP_SECONDS: i64 = 60 * 60;

/// THE REPEAT DAY. A copy whose last full hold ended with the copy forgotten
/// (it lapsed and the device rejoined) is held again within this long of that
/// hold's start only by a REPEAT hold, each shorter than the last
/// ([`repeat_hold_cap`]), and once those run out not at all: it rejoins as an
/// unenrolled group does. A FULL hold
/// the copy left by merging on (the commit came) costs nothing, and neither
/// does one the head check finds current at its cap: only a full hold that
/// ends with the head really past the copy starts the repeats. Once they
/// start, a repeat the copy settles by merging still counts, and the next
/// stall inside the day is the next repeat, never a full hold again. A
/// start a clock running ahead wrote is counted from the moment it is next
/// read, never from the future date.
pub const HOLD_REPEAT_SECONDS: i64 = 24 * 60 * 60;

/// The cap of the first repeat hold in a day ([`HOLD_REPEAT_SECONDS`]):
/// long enough for the client's `FetchCommitAt`, whose delay is drawn from a
/// quarter of the hold's length,
/// and its one retry, and for an online steward to veto.
pub const HOLD_REPEAT_CAP_SECONDS: i64 = 10 * 60;

/// The shortest repeat hold: a repeat whose halved cap would be shorter is
/// not entered.
pub const HOLD_REPEAT_MIN_SECONDS: i64 = 2 * 60;

/// The cap of the `repeat`-th repeat hold within a day (1 for the first):
/// [`HOLD_REPEAT_CAP_SECONDS`], halved for each repeat before it, or `None`
/// once that falls below [`HOLD_REPEAT_MIN_SECONDS`]. Ten minutes, five, two
/// and a half, then none.
pub fn repeat_hold_cap(repeat: u32) -> Option<i64> {
    let halvings = repeat.checked_sub(1)?;
    let cap = HOLD_REPEAT_CAP_SECONDS.checked_shr(halvings).unwrap_or(0);
    (cap >= HOLD_REPEAT_MIN_SECONDS).then_some(cap)
}

/// How long the steward key held at each epoch is kept, for judging a veto
/// of a commit this device merged.
pub const STEWARD_KEY_KEPT_SECONDS: i64 = 7 * 24 * 60 * 60;

/// A veto, as the frame carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedVeto {
    pub handle: [u8; 32],
    /// The epoch the vetoed commit was built in.
    pub epoch: u64,
    /// The vetoed commit's next verifier: the head's verifier of `epoch + 1`.
    pub vetoed_next: [u8; 32],
    /// The replacement's next verifier.
    pub replacement_next: [u8; 32],
    pub signature: [u8; 64],
}

impl SignedVeto {
    /// The bytes the frame carries.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNED_VETO_BYTES);
        out.push(SIGNED_VETO_VERSION);
        out.extend_from_slice(&self.handle);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.vetoed_next);
        out.extend_from_slice(&self.replacement_next);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Read a signed veto: exactly [`SIGNED_VETO_BYTES`], version 1.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNED_VETO_BYTES || bytes[0] != SIGNED_VETO_VERSION {
            return Err(Error::invalid("a signed veto is 169 bytes, version 1"));
        }
        let take32 = |at: usize| -> [u8; 32] {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes[at..at + 32]);
            out
        };
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&bytes[33..41]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[105..169]);
        Ok(Self {
            handle: take32(1),
            epoch: u64::from_be_bytes(epoch),
            vetoed_next: take32(41),
            replacement_next: take32(73),
            signature,
        })
    }

    /// What the steward key signed for this veto over `inner`.
    pub fn statement(&self, inner: &[u8]) -> Vec<u8> {
        let digest: [u8; 32] = Sha256::digest(inner).into();
        veto_statement(
            &self.handle,
            self.epoch,
            &self.vetoed_next,
            &digest,
            &self.replacement_next,
        )
    }

    /// Whether `steward_pub` signed this veto over `inner`.
    pub fn verify(&self, steward_pub: &[u8; 32], inner: &[u8]) -> bool {
        verify_statement(steward_pub, &self.statement(inner), &self.signature)
    }
}

/// `inner` wrapped in a veto frame. `inner` is a carried frame or a raw
/// commit: never empty, never another veto frame.
pub fn wrap_veto(veto: &SignedVeto, inner: &[u8]) -> Result<Vec<u8>> {
    if inner.is_empty() {
        return Err(Error::invalid("a vetoing commit is not empty"));
    }
    if inner.starts_with(&VETO_FRAME_MAGIC) {
        return Err(Error::invalid("a veto frame holds no veto frame"));
    }
    let signed = veto.to_bytes();
    let len = u16::try_from(signed.len()).map_err(|_| Error::invalid("a signed veto fits"))?;
    let mut out = Vec::with_capacity(4 + 2 + signed.len() + inner.len());
    out.extend_from_slice(&VETO_FRAME_MAGIC);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&signed);
    out.extend_from_slice(inner);
    Ok(out)
}

/// Split a commit entry into its signed veto (the frame's bytes) and what it
/// wraps: `(None, bytes)` when it is no veto frame. A frame that ends early,
/// whose length is not a signed veto's, that wraps nothing, or that wraps
/// another veto frame is refused.
pub fn split_veto(bytes: &[u8]) -> Result<(Option<&[u8]>, &[u8])> {
    let Some(rest) = bytes.strip_prefix(&VETO_FRAME_MAGIC[..]) else {
        return Ok((None, bytes));
    };
    let (len, rest) = rest
        .split_first_chunk::<2>()
        .ok_or_else(|| Error::invalid("a veto frame ends before its length"))?;
    let len = usize::from(u16::from_be_bytes(*len));
    if len != SIGNED_VETO_BYTES {
        return Err(Error::invalid("a veto frame's veto is 169 bytes"));
    }
    if rest.len() <= len {
        return Err(Error::invalid("a veto frame wraps a commit"));
    }
    let (signed, inner) = rest.split_at(len);
    if inner.starts_with(&VETO_FRAME_MAGIC) {
        return Err(Error::invalid("a veto frame holds no veto frame"));
    }
    Ok((Some(signed), inner))
}

/// `domain ‖ fields`, the statements the steward key signs.
fn statement(domain: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = domain.as_bytes().to_vec();
    for field in fields {
        out.extend_from_slice(field);
    }
    out
}

/// What a REPAIR signs: the handle, the head's epoch, the head's verifier
/// now (S) and the verifier that epoch really has (V).
pub fn repair_statement(handle: &[u8; 32], epoch: u64, s: &[u8; 32], v: &[u8; 32]) -> Vec<u8> {
    statement(STEWARD_REPAIR_DOMAIN, &[handle, &epoch.to_be_bytes(), s, v])
}

/// What a VETO signs: the handle, the epoch the vetoed commit was built in,
/// its next verifier, SHA-256 of the replacement entry the frame wraps, and
/// the replacement's next verifier.
pub fn veto_statement(
    handle: &[u8; 32],
    epoch: u64,
    vetoed_next: &[u8; 32],
    replacement_digest: &[u8; 32],
    replacement_next: &[u8; 32],
) -> Vec<u8> {
    statement(
        STEWARD_VETO_DOMAIN,
        &[
            handle,
            &epoch.to_be_bytes(),
            vetoed_next,
            replacement_digest,
            replacement_next,
        ],
    )
}

/// What a key CHANGE signs, under the key it replaces: the handle, the
/// epoch of the commit carrying it, the old key and the new.
pub fn change_statement(
    handle: &[u8; 32],
    epoch: u64,
    old_pub: &[u8; 32],
    new_pub: &[u8; 32],
) -> Vec<u8> {
    statement(
        STEWARD_CHANGE_DOMAIN,
        &[handle, &epoch.to_be_bytes(), old_pub, new_pub],
    )
}

/// The steward key's public half from its 32-byte seed.
pub fn steward_public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Sign `statement` with the steward key's seed.
pub fn sign_statement(seed: &[u8; 32], statement: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(statement).to_bytes()
}

/// Whether `signature` is the steward key's over `statement`. A plain bool:
/// a key that is not a point and a signature that does not hold mean the
/// same thing. `verify_strict`, so a small-order key verifies nothing.
pub fn verify_statement(steward_pub: &[u8; 32], statement: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(steward_pub) else {
        return false;
    };
    if key.is_weak() {
        return false;
    }
    key.verify_strict(statement, &Signature::from_bytes(signature))
        .is_ok()
}

/// The commit MAC under `mac_key` (the epoch's [`COMMIT_MAC_LABEL`] export):
/// HMAC-SHA256 over `S ‖ BE64(E) ‖ SHA-256(entry)`.
pub fn commit_mac(mac_key: &[u8], next_verifier: &[u8; 32], epoch: u64, entry: &[u8]) -> [u8; 32] {
    let digest: [u8; 32] = Sha256::digest(entry).into();
    // HMAC takes a key of any length, so this never fails.
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(mac_key) else {
        return [0u8; 32];
    };
    mac.update(next_verifier);
    mac.update(&epoch.to_be_bytes());
    mac.update(&digest);
    mac.finalize().into_bytes().into()
}

/// Whether `mac` is the commit MAC of `entry` under `mac_key`, compared in
/// constant time.
pub fn commit_mac_holds(
    mac_key: &[u8],
    next_verifier: &[u8; 32],
    epoch: u64,
    entry: &[u8],
    mac: &[u8; 32],
) -> bool {
    use subtle::ConstantTimeEq;
    commit_mac(mac_key, next_verifier, epoch, entry)
        .ct_eq(mac)
        .into()
}

fn hkdf32(send_key: &[u8], info: &str) -> zeroize::Zeroizing<[u8; 32]> {
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    // 32 bytes is far under HKDF-SHA256's limit, so this never fails.
    let _ = hkdf::Hkdf::<Sha256>::new(None, send_key).expand(info.as_bytes(), out.as_mut_slice());
    out
}

fn sealed_aad(epoch: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[0] = SEALED_VERSION;
    aad[1..].copy_from_slice(&epoch.to_be_bytes());
    aad
}

// Only the fixture and the tests seal: on a device the core only opens.
#[cfg(any(test, feature = "fixture"))]
fn seal_under(key: &[u8; 32], epoch: u64, plain: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::invalid("a 32-byte key"))?;
    let aad = sealed_aad(epoch);
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .map_err(|_| Error::invalid("could not seal"))?;
    let mut out = Vec::with_capacity(1 + 12 + sealed.len());
    out.push(SEALED_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open_under(key: &[u8; 32], epoch: u64, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < SEALED_OVERHEAD || sealed[0] != SEALED_VERSION {
        return Err(Error::invalid("not a version 1 sealed copy"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::invalid("a 32-byte key"))?;
    let aad = sealed_aad(epoch);
    cipher
        .decrypt(
            Nonce::from_slice(&sealed[1..13]),
            Payload {
                msg: &sealed[13..],
                aad: &aad,
            },
        )
        .map_err(|_| Error::invalid("the sealed copy does not open under this epoch's send key"))
}

/// What a sealed stamp says. A field of zeros is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    /// The verifier the commit's submitter named (S).
    pub next_verifier: [u8; 32],
    /// The handle's steward key when the commit was placed.
    pub steward_pub: Option<[u8; 32]>,
    /// The committer's MAC.
    pub mac: Option<[u8; 32]>,
}

fn none_if_zero(bytes: &[u8]) -> Option<[u8; 32]> {
    let arr = <[u8; 32]>::try_from(bytes).ok()?;
    (arr != [0u8; 32]).then_some(arr)
}

/// The server's seal of a stamp, with the nonce given: the fixture's and the
/// tests' door (the server seals stamps; no client does).
#[cfg(any(test, feature = "fixture"))]
pub fn seal_stamp_with_nonce(
    send_key: &[u8],
    epoch: u64,
    stamp: &Stamp,
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    let mut plain = Vec::with_capacity(96);
    plain.extend_from_slice(&stamp.next_verifier);
    plain.extend_from_slice(&stamp.steward_pub.unwrap_or([0u8; 32]));
    plain.extend_from_slice(&stamp.mac.unwrap_or([0u8; 32]));
    seal_under(&hkdf32(send_key, COMMIT_STAMP_INFO), epoch, &plain, nonce)
}

/// Open a sealed stamp with the send key of the epoch the commit was built
/// in.
pub fn open_stamp(send_key: &[u8], epoch: u64, sealed: &[u8]) -> Result<Stamp> {
    if sealed.len() != STAMP_BYTES {
        return Err(Error::invalid("a sealed stamp is 125 bytes"));
    }
    let plain = open_under(&hkdf32(send_key, COMMIT_STAMP_INFO), epoch, sealed)?;
    if plain.len() != 96 {
        return Err(Error::invalid("a stamp holds 96 bytes"));
    }
    let mut next_verifier = [0u8; 32];
    next_verifier.copy_from_slice(&plain[..32]);
    Ok(Stamp {
        next_verifier,
        steward_pub: none_if_zero(&plain[32..64]),
        mac: none_if_zero(&plain[64..96]),
    })
}

/// The server's seal of the head log's copy of a commit envelope, with the
/// nonce given: the fixture's and the tests' door.
#[cfg(any(test, feature = "fixture"))]
pub fn seal_log_copy_with_nonce(
    send_key: &[u8],
    epoch: u64,
    envelope: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    seal_under(&hkdf32(send_key, COMMIT_LOG_INFO), epoch, envelope, nonce)
}

/// Open the head log's copy of the commit built at `epoch` (FetchCommitAt)
/// with that epoch's send key: the commit envelope as it was placed.
pub fn open_log_copy(send_key: &[u8], epoch: u64, sealed: &[u8]) -> Result<Vec<u8>> {
    open_under(&hkdf32(send_key, COMMIT_LOG_INFO), epoch, sealed)
}

/// A REPAIR NOTICE, the lane frame a repairing admin sends the group:
///
/// ```text
/// {"peachy":"repair","v":1,"e":<head epoch>,"s":"<b64 S>","m":"<b64 mac, or empty>","w":"<b64 V>"}
/// ```
///
/// Standard padded base64. The sender is the MLS sender, never the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairNotice {
    pub epoch: u64,
    /// The verifier the head named (S).
    pub s: [u8; 32],
    /// The committer's MAC from the stamp, when it had one.
    pub mac: Option<[u8; 32]>,
    /// The verifier the repair put on the head (V).
    pub w: [u8; 32],
}

impl RepairNotice {
    /// The frame's wire.
    pub fn to_wire(&self) -> String {
        use base64::Engine as _;
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        serde_json::json!({
            "peachy": REPAIR_NOTICE_KIND,
            "v": 1,
            "e": self.epoch,
            "s": b64(&self.s),
            "m": self.mac.map(|m| b64(&m)).unwrap_or_default(),
            "w": b64(&self.w),
        })
        .to_string()
    }

    /// Read one, or `None` for anything else on the lane (another frame, a
    /// later version, a field missing or the wrong length).
    pub fn parse(wire: &[u8]) -> Option<Self> {
        use base64::Engine as _;
        let value: serde_json::Value = serde_json::from_slice(wire).ok()?;
        let map = value.as_object()?;
        if map.get("peachy")?.as_str()? != REPAIR_NOTICE_KIND || map.get("v")?.as_u64()? != 1 {
            return None;
        }
        let b32 = |key: &str| -> Option<[u8; 32]> {
            let text = map.get(key)?.as_str()?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(text)
                .ok()?;
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        };
        let mac = match map.get("m")?.as_str()? {
            "" => None,
            _ => Some(b32("m")?),
        };
        Some(Self {
            epoch: map.get("e")?.as_u64()?,
            s: b32("s")?,
            mac,
            w: b32("w")?,
        })
    }
}

/// What a device makes of a repair notice ([`RepairNotice`]), against the
/// verifier its own copy had at the notice's epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RepairNoticeVerdict {
    /// The repair put the head where this device's copy is, and the head
    /// had been elsewhere.
    Consistent = 0,
    /// The repair named a verifier this device's copy did not have at that
    /// epoch, or "repaired" a head that needed none: an admin repointing the
    /// head. Hold, and alert naming the sender.
    Inconsistent = 1,
    /// This device holds no verifier for that epoch, or the frame is not a
    /// repair notice: nothing to judge.
    Unjudged = 2,
}

impl RepairNotice {
    /// Judge this notice against `own`, this device's verifier at its epoch.
    pub fn judge(&self, own: Option<&[u8; 32]>) -> RepairNoticeVerdict {
        let Some(own) = own else {
            return RepairNoticeVerdict::Unjudged;
        };
        if self.s == self.w || &self.w != own {
            RepairNoticeVerdict::Inconsistent
        } else {
            RepairNoticeVerdict::Consistent
        }
    }
}

/// The steward key a group's meta names: `stw.k`, unpadded URL-safe base64
/// of 32 bytes. `None` for a meta with no `stw`, an unreadable one, or a key
/// of the wrong length; every such group behaves as one never enrolled.
pub fn steward_key_of_meta(meta: &[u8]) -> Option<[u8; 32]> {
    use base64::Engine as _;
    let value: serde_json::Value = serde_json::from_slice(meta).ok()?;
    let k = value.get("stw")?.get("k")?.as_str()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(k)
        .ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// Why a group is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum HoldReason {
    /// The commit at this device's epoch opened and was refused: a member
    /// built a commit this device cannot apply.
    RefusedCommit = 1,
    /// The commit at this device's epoch did not open, or was lost.
    UnopenableCommit = 2,
    /// A repair notice did not hold up.
    FalseRepair = 3,
}

impl HoldReason {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::RefusedCommit),
            2 => Some(Self::UnopenableCommit),
            3 => Some(Self::FalseRepair),
            _ => None,
        }
    }
}

/// THE GROUP HOLD: the one record each group may have that says this
/// device is waiting for a repair or a veto, rather than stranding or
/// rejoining. Persistent. Entered only in a group this device counts as
/// enrolled (`Client::group_hold`: its meta's `stw.k` is the key the server's
/// stamp named); left when a commit merges, on its cap, or by hand.
///
/// AT MOST ONE HOLD AN EPOCH: the record stays after it lapses, and the copy
/// is not held again at that epoch, so a device no steward rescues falls back
/// to rejoining within [`HOLD_CAP_SECONDS`] of its first hold there, however
/// many triggers follow. A clock set back before `since` lapses it too, so no
/// clock change stretches it past `until`.
///
/// While held the device makes no commit of its own, links no device and
/// answers no seat ask, and every rejoin path (`commit_strands`, the
/// clients' fork and stuck-behind rules, the lost-commit recovery) waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupHold {
    /// The epoch the device was at when it was held.
    pub epoch: u64,
    /// Unix seconds.
    pub since: i64,
    /// Unix seconds; the hold lapses at this time.
    pub until: i64,
    pub reason: HoldReason,
}

impl GroupHold {
    /// This hold as JSON, the form every binding hands it out in:
    /// `{"epoch","since","until","reason"}`.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// A hold entered at `now` for `epoch`, for the full [`HOLD_CAP_SECONDS`].
    pub fn new(epoch: u64, now: i64, reason: HoldReason) -> Self {
        Self::with_cap(epoch, now, HOLD_CAP_SECONDS, reason)
    }

    /// A hold entered at `now` for `epoch` that lapses `cap` seconds later
    /// (a repeat hold, [`repeat_hold_cap`]).
    pub fn with_cap(epoch: u64, now: i64, cap: i64, reason: HoldReason) -> Self {
        Self {
            epoch,
            since: now,
            until: now.saturating_add(cap),
            reason,
        }
    }

    /// Whether this hold still holds at `now`, for a device at `epoch`: a
    /// lapsed hold, one a later epoch has left behind, or one whose clock
    /// now reads before it began, does not.
    pub fn holds(&self, now: i64, epoch: u64) -> bool {
        epoch == self.epoch && now >= self.since && now < self.until
    }
}

/// Whether `actor` is among the admins (`adm`) a group's meta names. False
/// for a meta with no `adm`, an unreadable one, or anything else.
pub fn meta_names_admin(meta: &[u8], actor: &str) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(meta) else {
        return false;
    };
    value
        .get("adm")
        .and_then(|adm| adm.as_array())
        .is_some_and(|adm| adm.iter().any(|a| a.as_str() == Some(actor)))
}

/// Whether a commit by `actor` on a group whose meta was `prior` (before the
/// commit) may change the steward key the group COUNTS for enrollment
/// (`Client::enrolled_steward_key`): an admin of `prior`, or any member of a
/// group whose meta names no admins at all (a direct chat, a flat group, a
/// group with no meta yet). A plain member's change to `stw` is merged as
/// ever, and only does not count, so it neither enrolls nor un-enrolls the
/// group. Fails closed: an `adm` that does not read names no admin, and an
/// empty `actor` (a lapsed committer) is nobody.
///
/// This is local and refuses nothing: no build writes a steward
/// (`STEWARD_WRITES` is false), and a plain member's `stw` change is not a
/// key the policy governs.
pub fn may_change_steward_key(prior: Option<&[u8]>, actor: &str) -> bool {
    let Some(prior) = prior else {
        return true;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(prior) else {
        return false;
    };
    match value.get("adm") {
        None => true,
        Some(serde_json::Value::Array(adm)) if adm.is_empty() => true,
        Some(serde_json::Value::Array(adm)) => {
            !actor.is_empty() && adm.iter().any(|a| a.as_str() == Some(actor))
        }
        Some(_) => false,
    }
}

/// What the commit door found when it checked a commit's sealed stamp
/// against what the commit really did (`Client::take_commit_check`). It
/// only ALERTS on it: nothing here refuses a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StampVerdict {
    /// The commit came with no stamp (a server before stamps, or none).
    Absent,
    /// The stamp did not open under the epoch's send key: the server's
    /// stamp is not for this commit's epoch.
    Unopened,
    /// The head names the verifier the commit really produces.
    Match,
    /// The head names another verifier, and the committer's MAC holds: the
    /// committer lied, and is blamed by account.
    Blame,
    /// The head names another verifier and the MAC is missing or does not
    /// hold: the server and the committer cannot be told apart; repair, no
    /// blame.
    Repair,
    /// This device cannot compute the verifier (the commit removed it).
    Unjudged,
}

/// One commit's check, as `Client::take_commit_check` hands it out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommitCheck {
    /// The epoch the commit was built in.
    pub epoch: u64,
    pub stamp: StampVerdict,
    /// The account the commit's MLS sender is, when the verdict is `blame`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blame: Option<String>,
    /// Whether the MAC was present and held, absent, or did not hold.
    pub mac: MacVerdict,
    /// The steward key check: the key the stamp names against the key the
    /// meta named at the commit's epoch.
    pub steward: StewardVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacVerdict {
    Missing,
    Valid,
    Invalid,
    /// No stamp to read one from.
    Unread,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StewardVerdict {
    /// Neither the meta nor the stamp names a key.
    None,
    /// The stamp names the key the meta held at the epoch.
    Match,
    /// They differ: the server holds a key the group did not give it, or
    /// lost the one it did. An alert.
    Mismatch,
    /// No stamp to compare.
    Unread,
}

impl CommitCheck {
    /// This check as JSON, the form every binding hands it out in:
    /// `{"epoch","stamp","mac","steward"}`, and `"blame"` when set.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Whether this check is worth an alert: anything but a matching
    /// stamp, an absent one, or one this device could not judge.
    pub fn alerts(&self) -> bool {
        !matches!(
            self.stamp,
            StampVerdict::Absent | StampVerdict::Match | StampVerdict::Unjudged
        ) || matches!(self.steward, StewardVerdict::Mismatch)
    }
}

/// What a veto means to this device (`Client::judge_veto`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VetoVerdict {
    /// No veto frame, one for another handle or a later epoch, a veto that
    /// does not verify under the steward key held at its epoch, or a valid
    /// veto of a commit this copy did not merge.
    None = 0,
    /// A valid veto of the commit at this device's own epoch: skip the
    /// vetoed commit, and take the replacement.
    SkipVetoed = 1,
    /// A valid veto of a commit this device already merged: its copy is on
    /// the vetoed branch, and it rejoins without waiting.
    RejoinNow = 2,
    /// A veto frame for this handle, of an earlier epoch that this copy
    /// cannot judge under a key it kept: the epoch's successor is more than
    /// 63 epochs behind it or before its seat (a device the vetoed commit,
    /// or a later one on its branch, seated), or it kept no steward key for
    /// that epoch. Signed or not: the copy cannot tell whether it merged the
    /// vetoed commit, so it does not rejoin on the frame's word; it reads
    /// the group's head now, through the fork check and its backoff, as
    /// after messages that would not open. A forged or replayed frame so
    /// buys nothing a commit that will not open, or a lying head, could not
    /// already do.
    CheckHead = 3,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const HANDLE: [u8; 32] = [7u8; 32];
    const SEED: [u8; 32] = [9u8; 32];

    fn veto(inner: &[u8]) -> SignedVeto {
        let mut v = SignedVeto {
            handle: HANDLE,
            epoch: 5,
            vetoed_next: [1u8; 32],
            replacement_next: [2u8; 32],
            signature: [0u8; 64],
        };
        v.signature = sign_statement(&SEED, &v.statement(inner));
        v
    }

    #[test]
    fn the_veto_magic_is_neither_a_raw_commit_nor_a_carried_frame() {
        assert_eq!(VETO_FRAME_MAGIC[0], 0xff);
        assert_ne!(
            VETO_FRAME_MAGIC,
            crate::carried_commit::CARRIED_COMMIT_MAGIC
        );
    }

    #[test]
    fn a_veto_frame_round_trips_and_verifies() {
        let inner = [0x00, 0x01, 0xaa];
        let v = veto(&inner);
        let framed = wrap_veto(&v, &inner).unwrap();
        assert_eq!(&framed[..4], &VETO_FRAME_MAGIC);
        assert_eq!(&framed[4..6], &169u16.to_be_bytes());
        let (signed, rest) = split_veto(&framed).unwrap();
        let parsed = SignedVeto::from_bytes(signed.unwrap()).unwrap();
        assert_eq!(parsed, v);
        assert_eq!(rest, inner);
        assert!(parsed.verify(&steward_public_key(&SEED), rest));
        assert!(!parsed.verify(&steward_public_key(&[8u8; 32]), rest));
        assert!(!parsed.verify(&steward_public_key(&SEED), &[0x00, 0x01, 0xab]));
    }

    #[test]
    fn a_bad_veto_frame_is_refused() {
        let inner = [0x00, 0x01, 0xaa];
        let framed = wrap_veto(&veto(&inner), &inner).unwrap();
        assert!(split_veto(&framed[..6 + 169]).is_err(), "wraps nothing");
        assert!(split_veto(&framed[..5]).is_err(), "no length");
        let mut short = framed.clone();
        short[5] = 168;
        assert!(split_veto(&short).is_err(), "wrong length");
        let mut nested = framed[..6 + 169].to_vec();
        nested.extend_from_slice(&framed);
        assert!(split_veto(&nested).is_err(), "a veto in a veto");
        assert!(wrap_veto(&veto(&inner), &framed).is_err());
        assert!(wrap_veto(&veto(&inner), &[]).is_err());
        assert_eq!(split_veto(&inner).unwrap(), (None, &inner[..]));
    }

    #[test]
    fn the_stamp_opens_only_under_its_epochs_send_key() {
        let stamp = Stamp {
            next_verifier: [3u8; 32],
            steward_pub: Some([4u8; 32]),
            mac: None,
        };
        let sealed = seal_stamp_with_nonce(b"send key", 9, &stamp, &[5u8; 12]).unwrap();
        assert_eq!(sealed.len(), STAMP_BYTES);
        assert_eq!(open_stamp(b"send key", 9, &sealed).unwrap(), stamp);
        assert!(open_stamp(b"send key", 10, &sealed).is_err());
        assert!(open_stamp(b"other key", 9, &sealed).is_err());
        let copy = seal_log_copy_with_nonce(b"send key", 9, b"envelope", &[6u8; 12]).unwrap();
        assert_eq!(copy.len(), b"envelope".len() + SEALED_OVERHEAD);
        assert_eq!(open_log_copy(b"send key", 9, &copy).unwrap(), b"envelope");
        assert!(open_log_copy(b"send key", 8, &copy).is_err());
        // The stamp's key is not the log's.
        assert!(open_stamp(b"send key", 9, &copy).is_err());
    }

    #[test]
    fn the_mac_binds_verifier_epoch_and_entry() {
        let mac = commit_mac(b"k", &[1u8; 32], 3, b"entry");
        assert!(commit_mac_holds(b"k", &[1u8; 32], 3, b"entry", &mac));
        assert!(!commit_mac_holds(b"k", &[2u8; 32], 3, b"entry", &mac));
        assert!(!commit_mac_holds(b"k", &[1u8; 32], 4, b"entry", &mac));
        assert!(!commit_mac_holds(b"k", &[1u8; 32], 3, b"entrz", &mac));
        assert!(!commit_mac_holds(b"j", &[1u8; 32], 3, b"entry", &mac));
    }

    #[test]
    fn only_an_admin_changes_the_counted_steward_key_where_there_are_admins() {
        let admins = br#"{"v":1,"adm":["ada"]}"#.as_slice();
        assert!(may_change_steward_key(Some(admins), "ada"));
        assert!(!may_change_steward_key(Some(admins), "bo"));
        assert!(
            !may_change_steward_key(Some(admins), ""),
            "a lapsed committer is nobody"
        );
        assert!(
            may_change_steward_key(Some(br#"{"v":1}"#), "bo"),
            "no admins: any member"
        );
        assert!(may_change_steward_key(Some(br#"{"v":1,"adm":[]}"#), "bo"));
        assert!(may_change_steward_key(None, "bo"), "no meta yet");
        assert!(
            !may_change_steward_key(Some(br#"{"v":1,"adm":"ada"}"#), "ada"),
            "closed"
        );
        assert!(!may_change_steward_key(Some(b"not json"), "ada"), "closed");
    }

    #[test]
    fn a_repair_notice_round_trips_and_is_judged() {
        let notice = RepairNotice {
            epoch: 4,
            s: [1u8; 32],
            mac: None,
            w: [2u8; 32],
        };
        let wire = notice.to_wire();
        assert_eq!(RepairNotice::parse(wire.as_bytes()).unwrap(), notice);
        assert_eq!(
            notice.judge(Some(&[2u8; 32])),
            RepairNoticeVerdict::Consistent
        );
        assert_eq!(
            notice.judge(Some(&[3u8; 32])),
            RepairNoticeVerdict::Inconsistent
        );
        assert_eq!(notice.judge(None), RepairNoticeVerdict::Unjudged);
        let needless = RepairNotice {
            w: [1u8; 32],
            ..notice.clone()
        };
        assert_eq!(
            needless.judge(Some(&[1u8; 32])),
            RepairNoticeVerdict::Inconsistent
        );
        assert!(RepairNotice::parse(br#"{"peachy":"hello","v":1}"#).is_none());
        assert!(
            RepairNotice::parse(br#"{"peachy":"repair","v":2,"e":1,"s":"","m":"","w":""}"#)
                .is_none()
        );
    }

    #[test]
    fn the_meta_names_a_steward_key_only_when_it_reads() {
        use base64::Engine as _;
        let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([5u8; 32]);
        let meta = format!(r#"{{"v":1,"n":"x","stw":{{"k":"{k}","b":{{}}}}}}"#);
        assert_eq!(steward_key_of_meta(meta.as_bytes()), Some([5u8; 32]));
        assert_eq!(steward_key_of_meta(br#"{"v":1,"n":"x"}"#), None);
        assert_eq!(steward_key_of_meta(br#"{"v":1,"stw":{"k":"AAAA"}}"#), None);
        assert_eq!(steward_key_of_meta(b"not json"), None);
    }

    #[test]
    fn a_hold_lapses_at_its_cap_and_at_a_later_epoch() {
        let hold = GroupHold::new(4, 1_000, HoldReason::RefusedCommit);
        assert!(hold.holds(1_000 + HOLD_CAP_SECONDS - 1, 4));
        assert!(!hold.holds(1_000 + HOLD_CAP_SECONDS, 4));
        assert!(!hold.holds(1_001, 5));
        // A clock set back before the hold began lapses it, so turning the
        // clock back never buys a longer hold.
        assert!(!hold.holds(999, 4));
    }

    #[test]
    fn repeat_holds_halve_and_then_run_out() {
        assert_eq!(repeat_hold_cap(0), None);
        assert_eq!(repeat_hold_cap(1), Some(600));
        assert_eq!(repeat_hold_cap(2), Some(300));
        assert_eq!(repeat_hold_cap(3), Some(150));
        assert_eq!(repeat_hold_cap(4), None);
        assert_eq!(repeat_hold_cap(u32::MAX), None);
        let hold = GroupHold::with_cap(4, 1_000, 150, HoldReason::RefusedCommit);
        assert!(hold.holds(1_149, 4));
        assert!(!hold.holds(1_150, 4));
    }

    #[test]
    fn the_meta_names_an_admin_only_in_adm() {
        let meta = br#"{"v":1,"adm":["ada","bo"],"n":"x"}"#;
        assert!(meta_names_admin(meta, "ada"));
        assert!(!meta_names_admin(meta, "cy"));
        assert!(!meta_names_admin(br#"{"v":1,"n":"ada"}"#, "ada"));
        assert!(!meta_names_admin(br#"{"adm":"ada"}"#, "ada"));
        assert!(!meta_names_admin(b"not json", "ada"));
    }
}
