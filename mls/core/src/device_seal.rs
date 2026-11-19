// SPDX-License-Identifier: MIT
//! The device seal: one 226-byte box per recipient device that rides beside a
//! version 3 envelope and tells that one device which group the envelope is
//! for, who sent it and the epoch envelope secret it was sealed under, with no
//! group state at all.
//!
//! A version 3 envelope opens only for a device whose copy of the group holds
//! the epoch it was sealed at. A copy that forked or fell behind holds none of
//! the epochs it missed, so the envelope opens for no group and cannot be
//! attributed. The device seal is sealed to the recipient DEVICE's long-term
//! key instead, so it opens whatever the group state, and the sender itself
//! hands the secret over: no epoch window, no other member in the path.
//!
//! ## The key: the device key every device already has
//!
//! The seal is sealed to the recipient's Ed25519 device key (the `device_key`
//! of its credential, which is the signature key of its leaf) used as X25519,
//! exactly as the account-key box does ([`crate::account_store`]): the public
//! key through the birational map, the secret the first half of SHA-512 over
//! the seed. A sender reads the key off the leaf in its own tree, where the
//! leaf's credential and account certificate were checked when it came in.
//! Nothing is published and nothing is looked up.
//!
//! ## The format
//!
//! ```text
//! seal = 0x01 || E(32) || c1(48) || c2(145)                      226 bytes
//! E    = X25519(e, 9), e fresh per seal
//! k1   = HKDF-SHA256(ikm = X25519(e, R), salt = <empty>,
//!                    info = "peachy device seal v1 sender" || 0x00 || E || R_ed, L = 32)
//! c1   = AES-256-GCM(k1, nonce = 0^12, S_ed, aad = 0x01 || E)
//! k2   = HKDF-SHA256(ikm = X25519(e, R) || X25519(s, R), salt = <empty>,
//!                    info = "peachy device seal v1 body" || 0x00 || E || R_ed || S_ed || c1, L = 32)
//! c2   = AES-256-GCM(k2, nonce = 0^12, body, aad = 0x01 || E || c1)
//! body = len(group id) (1) || group id || zeros to 64 bytes
//!        || epoch envelope secret (32) || SHA-256(envelope) (32)       129 bytes
//! ```
//!
//! `R_ed` and `S_ed` are the recipient's and the sender's Ed25519 public keys,
//! `R` the recipient's as X25519, `s` the sender's X25519 secret.
//!
//! - **Two layers.** The first, under the ephemeral agreement alone, carries
//!   the sender's key, so nobody but the recipient learns who sent it. The
//!   second adds the static agreement between the sender's key and the
//!   recipient's, which only those two can compute: a seal that opens was
//!   made by the holder of `S_ed`, or by the recipient itself, or by anyone
//!   who holds the recipient's key (key-compromise impersonation). That
//!   makes it a member's word, not proof of who wrote the message inside:
//!   the receiver holds a message that opens through a seal to the seal's
//!   sender ([`crate::group::Client::process_message_as`]). There is no
//!   signature on the seal, though the MLS message inside is signed by its
//!   author as any is.
//! - **The sign bit.** The map to X25519 drops the Ed25519 sign bit, so the
//!   holder of `S_ed`'s secret could name `-S_ed` in the first layer and
//!   still open the second. Harmless: `S_ed` is bound into the second
//!   layer's key, and a receiver compares it byte for byte with a leaf's
//!   signature key, which `-S_ed` is not.
//! - **No forward secrecy.** The seal is sealed to the recipient's
//!   long-term device key. Whoever later learns that key opens every
//!   recorded seal sent to it: the group id and the epoch envelope secret,
//!   which opens that one envelope to the MLS message inside (still under
//!   the group's keys).
//! - **A zero nonce.** Each key is used once, since `e` is fresh per seal.
//! - **The digest** binds the seal to its one envelope.
//! - **Constant length.** A group id longer than
//!   [`DEVICE_SEAL_MAX_GROUP_ID_BYTES`] gets no seal, so every seal is
//!   [`DEVICE_SEAL_BYTES`] long whatever it carries.
//!
//! A seal that does not open, for any reason, is one error with one message:
//! the reader learns nothing about which check failed.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::credential::ED25519_PUBLIC_KEY_BYTES;
use crate::error::{Error, Result};
use crate::identity::{signing_key_public_key, ED25519_SEED_BYTES};
use crate::secret::Secret;

/// The seal's format byte.
pub const DEVICE_SEAL_VERSION: u8 = 0x01;
/// The longest group id a seal carries. A longer one gets no seal.
pub const DEVICE_SEAL_MAX_GROUP_ID_BYTES: usize = 64;
/// The seal's body: the group id's length and slot, the epoch envelope
/// secret, the envelope's digest.
pub const DEVICE_SEAL_BODY_BYTES: usize = 1 + DEVICE_SEAL_MAX_GROUP_ID_BYTES + 32 + 32;
/// Every seal's length.
pub const DEVICE_SEAL_BYTES: usize = 1 + 32 + (32 + 16) + (DEVICE_SEAL_BODY_BYTES + 16);
/// The HKDF domain of the key the sender's key is sealed under.
pub const DEVICE_SEAL_SENDER_DOMAIN: &str = "peachy device seal v1 sender";
/// The HKDF domain of the key the body is sealed under.
pub const DEVICE_SEAL_BODY_DOMAIN: &str = "peachy device seal v1 body";
/// Whether this build WRITES seals. No build writes a seal: DEVICE_SEAL_SENDS
/// is false and every build reads one, so the seal is not in the published
/// specification.
pub const DEVICE_SEAL_SENDS: bool = false;

const OPAQUE: &str = "the device seal does not open";

/// What a seal told its recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedSeal {
    /// The sender device's Ed25519 public key: whoever made the seal holds
    /// its secret.
    pub sender_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    /// The group the envelope is for.
    pub group_id: Vec<u8>,
    /// The epoch envelope secret it was sealed under.
    pub epoch_secret: Secret<[u8; 32]>,
}

/// Seal, for the device whose Ed25519 key is `recipient_key`, the group id
/// and epoch envelope secret of `envelope`, from the device whose seed is
/// `sender_seed`. [`DEVICE_SEAL_BYTES`] long.
pub fn device_seal(
    sender_seed: &[u8],
    recipient_key: &[u8],
    group_id: &[u8],
    epoch_secret: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>> {
    seal_from_seed(
        sender_seed,
        recipient_key,
        group_id,
        epoch_secret,
        envelope,
        &*fresh_ephemeral()?,
    )
}

/// [`device_seal`] with the ephemeral secret given: the golden fixture's door
/// alone, compiled only into tests and the `fixture` build. An ephemeral used
/// twice uses the body layer's key and nonce twice, so nothing that ships can
/// reach this.
#[cfg(any(test, feature = "fixture"))]
#[doc(hidden)]
pub fn device_seal_with_ephemeral(
    sender_seed: &[u8],
    recipient_key: &[u8],
    group_id: &[u8],
    epoch_secret: &[u8],
    envelope: &[u8],
    ephemeral: &[u8],
) -> Result<Vec<u8>> {
    let ephemeral: Zeroizing<[u8; 32]> = Zeroizing::new(
        ephemeral
            .try_into()
            .map_err(|_| Error::invalid("an ephemeral secret must be 32 bytes"))?,
    );
    seal_from_seed(
        sender_seed,
        recipient_key,
        group_id,
        epoch_secret,
        envelope,
        &ephemeral,
    )
}

fn seal_from_seed(
    sender_seed: &[u8],
    recipient_key: &[u8],
    group_id: &[u8],
    epoch_secret: &[u8],
    envelope: &[u8],
    ephemeral: &[u8; 32],
) -> Result<Vec<u8>> {
    let sender_seed: Zeroizing<[u8; ED25519_SEED_BYTES]> = Zeroizing::new(
        sender_seed
            .try_into()
            .map_err(|_| Error::invalid("a sender seed must be 32 bytes"))?,
    );
    let sender_key = signing_key_public_key(sender_seed.as_slice())?;
    seal_keyed(
        &x25519_secret(&sender_seed),
        &sender_key,
        recipient_key,
        group_id,
        epoch_secret,
        envelope,
        ephemeral,
    )
}

/// 32 fresh random bytes for one seal's ephemeral key, wiped when it goes.
fn fresh_ephemeral() -> Result<Zeroizing<[u8; 32]>> {
    let mut ephemeral = Zeroizing::new([0u8; 32]);
    getrandom::fill(ephemeral.as_mut_slice())
        .map_err(|err| Error::invalid(format!("no system randomness available: {err}")))?;
    Ok(ephemeral)
}

/// [`device_seal`] from the secret [`device_seal_secret`] derived and the
/// sender's own public key: what a [`crate::group::Client`] seals with.
pub(crate) fn device_seal_keyed(
    sender_secret: &[u8; 32],
    sender_key: &[u8],
    recipient_key: &[u8],
    group_id: &[u8],
    epoch_secret: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>> {
    let sender_key: [u8; ED25519_PUBLIC_KEY_BYTES] = sender_key
        .try_into()
        .map_err(|_| Error::invalid("a sender key must be 32 bytes"))?;
    seal_keyed(
        sender_secret,
        &sender_key,
        recipient_key,
        group_id,
        epoch_secret,
        envelope,
        &*fresh_ephemeral()?,
    )
}

/// Whether a device seal can be made for `key`: a key in its one spelling
/// and of the prime order ([`montgomery`]). A leaf whose key is not gets 226
/// random bytes in its seal's place ([`crate::group::Client::device_seals`]).
pub(crate) fn device_key_is_sealable(key: &[u8]) -> bool {
    <[u8; ED25519_PUBLIC_KEY_BYTES]>::try_from(key)
        .ok()
        .is_some_and(|key| montgomery(&key).is_ok())
}

/// 226 random bytes behind the version byte, in place of a seal for a device
/// no seal can be made for: every entry of a send carries one of the same
/// length and the same first byte. It opens for nobody.
pub(crate) fn device_seal_filler() -> Result<Vec<u8>> {
    let mut filler = vec![0u8; DEVICE_SEAL_BYTES];
    getrandom::fill(&mut filler)
        .map_err(|err| Error::invalid(format!("no system randomness available: {err}")))?;
    filler[0] = DEVICE_SEAL_VERSION;
    Ok(filler)
}

fn seal_keyed(
    sender_secret: &[u8; 32],
    sender_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    recipient_key: &[u8],
    group_id: &[u8],
    epoch_secret: &[u8],
    envelope: &[u8],
    ephemeral: &[u8; 32],
) -> Result<Vec<u8>> {
    let recipient_key: [u8; ED25519_PUBLIC_KEY_BYTES] = recipient_key
        .try_into()
        .map_err(|_| Error::invalid("a recipient key must be 32 bytes"))?;
    let epoch_secret: Zeroizing<[u8; 32]> = Zeroizing::new(
        epoch_secret
            .try_into()
            .map_err(|_| Error::invalid("an epoch envelope secret must be 32 bytes"))?,
    );
    if group_id.is_empty() || group_id.len() > DEVICE_SEAL_MAX_GROUP_ID_BYTES {
        return Err(Error::invalid(format!(
            "a sealed group id is 1 to {DEVICE_SEAL_MAX_GROUP_ID_BYTES} bytes, got {}",
            group_id.len()
        )));
    }
    let group_len = u8::try_from(group_id.len())
        .map_err(|_| Error::invalid("a sealed group id is too long"))?;

    let recipient = montgomery(&recipient_key)?;
    let e_public = MontgomeryPoint::mul_base_clamped(*ephemeral).to_bytes();
    let ephemeral_shared = shared(recipient, ephemeral)?;
    let static_shared = shared(recipient, sender_secret)?;

    let k1 = sender_layer_key(&ephemeral_shared, &e_public, &recipient_key)?;
    let c1 = seal_aes(&k1, sender_key, &header(&e_public, &[]))?;
    let k2 = body_layer_key(
        &ephemeral_shared,
        &static_shared,
        &e_public,
        &recipient_key,
        sender_key,
        &c1,
    )?;

    let mut body = Zeroizing::new(Vec::with_capacity(DEVICE_SEAL_BODY_BYTES));
    body.push(group_len);
    body.extend_from_slice(group_id);
    body.resize(1 + DEVICE_SEAL_MAX_GROUP_ID_BYTES, 0);
    body.extend_from_slice(epoch_secret.as_slice());
    body.extend_from_slice(&Sha256::digest(envelope));
    let c2 = seal_aes(&k2, &body, &header(&e_public, &c1))?;

    let mut seal = Vec::with_capacity(DEVICE_SEAL_BYTES);
    seal.push(DEVICE_SEAL_VERSION);
    seal.extend_from_slice(&e_public);
    seal.extend_from_slice(&c1);
    seal.extend_from_slice(&c2);
    if seal.len() != DEVICE_SEAL_BYTES {
        return Err(Error::invalid("a device seal came out the wrong length"));
    }
    Ok(seal)
}

/// Open a seal with this device's own seed, for `envelope`: who sent it, the
/// group and the epoch envelope secret. Refuses, with one message whatever
/// the reason, a seal of another length or version, one for another device,
/// one whose layers do not open, one for another envelope, and one whose body
/// is not in its one spelling.
pub fn device_seal_open(recipient_seed: &[u8], seal: &[u8], envelope: &[u8]) -> Result<OpenedSeal> {
    open_inner(recipient_seed, seal, envelope).map_err(|_| Error::invalid(OPAQUE))
}

fn open_inner(recipient_seed: &[u8], seal: &[u8], envelope: &[u8]) -> Result<OpenedSeal> {
    let recipient_seed: [u8; ED25519_SEED_BYTES] = recipient_seed
        .try_into()
        .map_err(|_| Error::invalid(OPAQUE))?;
    let recipient_key = signing_key_public_key(&recipient_seed)?;
    open_keyed(
        &x25519_secret(&recipient_seed),
        &recipient_key,
        seal,
        envelope,
    )
}

/// The secret that opens device seals to the device holding `seed`, derived
/// once: what a [`crate::group::Client`] keeps instead of the seed itself,
/// wiped when it goes. It is as secret as the seed: clamped, it is the
/// device's Ed25519 signing scalar.
pub(crate) fn device_seal_secret(seed: &[u8; ED25519_SEED_BYTES]) -> Zeroizing<[u8; 32]> {
    x25519_secret(seed)
}

/// [`device_seal_open`] with the secret [`device_seal_secret`] derived and the
/// device's own public key.
pub(crate) fn device_seal_open_keyed(
    secret: &[u8; 32],
    recipient_key: &[u8],
    seal: &[u8],
    envelope: &[u8],
) -> Result<OpenedSeal> {
    let recipient_key: [u8; ED25519_PUBLIC_KEY_BYTES] = recipient_key
        .try_into()
        .map_err(|_| Error::invalid(OPAQUE))?;
    open_keyed(secret, &recipient_key, seal, envelope).map_err(|_| Error::invalid(OPAQUE))
}

fn open_keyed(
    secret: &[u8; 32],
    recipient_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    seal: &[u8],
    envelope: &[u8],
) -> Result<OpenedSeal> {
    if seal.len() != DEVICE_SEAL_BYTES {
        return Err(Error::invalid(OPAQUE));
    }
    let (version, rest) = seal.split_first().ok_or_else(|| Error::invalid(OPAQUE))?;
    if *version != DEVICE_SEAL_VERSION {
        return Err(Error::invalid(OPAQUE));
    }
    let (e_public, rest) = rest
        .split_at_checked(32)
        .ok_or_else(|| Error::invalid(OPAQUE))?;
    let (c1, c2) = rest
        .split_at_checked(48)
        .ok_or_else(|| Error::invalid(OPAQUE))?;
    let e_public: [u8; 32] = e_public.try_into().map_err(|_| Error::invalid(OPAQUE))?;

    let ephemeral_shared = shared(MontgomeryPoint(e_public), secret)?;
    let k1 = sender_layer_key(&ephemeral_shared, &e_public, recipient_key)?;
    let sender_key = open_aes(&k1, c1, &header(&e_public, &[]))?;
    let sender_key: [u8; ED25519_PUBLIC_KEY_BYTES] = sender_key
        .as_slice()
        .try_into()
        .map_err(|_| Error::invalid(OPAQUE))?;
    let static_shared = shared(montgomery(&sender_key)?, secret)?;
    let k2 = body_layer_key(
        &ephemeral_shared,
        &static_shared,
        &e_public,
        recipient_key,
        &sender_key,
        c1,
    )?;
    let body = Zeroizing::new(open_aes(&k2, c2, &header(&e_public, c1))?);

    let (group_len, rest) = body.split_first().ok_or_else(|| Error::invalid(OPAQUE))?;
    let (slot, rest) = rest
        .split_at_checked(DEVICE_SEAL_MAX_GROUP_ID_BYTES)
        .ok_or_else(|| Error::invalid(OPAQUE))?;
    let group_len = usize::from(*group_len);
    if group_len == 0 || group_len > DEVICE_SEAL_MAX_GROUP_ID_BYTES {
        return Err(Error::invalid(OPAQUE));
    }
    let (group_id, fill) = slot
        .split_at_checked(group_len)
        .ok_or_else(|| Error::invalid(OPAQUE))?;
    if fill.iter().any(|byte| *byte != 0) {
        return Err(Error::invalid(OPAQUE));
    }
    let (secret, digest) = rest
        .split_at_checked(32)
        .ok_or_else(|| Error::invalid(OPAQUE))?;
    let epoch_secret: Secret<[u8; 32]> =
        Secret::new(<[u8; 32]>::try_from(secret).map_err(|_| Error::invalid(OPAQUE))?);
    let expected = Sha256::digest(envelope);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(digest, expected.as_slice())) {
        return Err(Error::invalid(OPAQUE));
    }
    Ok(OpenedSeal {
        sender_key,
        group_id: group_id.to_vec(),
        epoch_secret,
    })
}

/// `0x01 || E || extra`: the associated data of each layer.
fn header(e_public: &[u8; 32], extra: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 32 + extra.len());
    aad.push(DEVICE_SEAL_VERSION);
    aad.extend_from_slice(e_public);
    aad.extend_from_slice(extra);
    aad
}

fn sender_layer_key(
    ephemeral_shared: &[u8; 32],
    e_public: &[u8; 32],
    recipient_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut info = Vec::with_capacity(DEVICE_SEAL_SENDER_DOMAIN.len() + 1 + 64);
    info.extend_from_slice(DEVICE_SEAL_SENDER_DOMAIN.as_bytes());
    info.push(0);
    info.extend_from_slice(e_public);
    info.extend_from_slice(recipient_key);
    hkdf32(ephemeral_shared, &info)
}

fn body_layer_key(
    ephemeral_shared: &[u8; 32],
    static_shared: &[u8; 32],
    e_public: &[u8; 32],
    recipient_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    sender_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    c1: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    for (slot, byte) in ikm
        .iter_mut()
        .zip(ephemeral_shared.iter().chain(static_shared.iter()))
    {
        *slot = *byte;
    }
    let mut info = Vec::with_capacity(DEVICE_SEAL_BODY_DOMAIN.len() + 1 + 96 + c1.len());
    info.extend_from_slice(DEVICE_SEAL_BODY_DOMAIN.as_bytes());
    info.push(0);
    info.extend_from_slice(e_public);
    info.extend_from_slice(recipient_key);
    info.extend_from_slice(sender_key);
    info.extend_from_slice(c1);
    hkdf32(ikm.as_slice(), &info)
}

fn hkdf32(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, out.as_mut_slice())
        .map_err(|_| Error::invalid("HKDF could not expand 32 bytes"))?;
    Ok(out)
}

fn seal_aes(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::invalid("an AES-256 key must be 32 bytes"))?
        .encrypt(
            Nonce::from_slice(&[0u8; 12]),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::invalid("AES-GCM could not seal"))
}

fn open_aes(key: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::invalid(OPAQUE))?
        .decrypt(
            Nonce::from_slice(&[0u8; 12]),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::invalid(OPAQUE))
}

/// An Ed25519 seed's X25519 secret: the first half of SHA-512 over it, which
/// the agreement clamps. Clamped, that is the Ed25519 signing scalar itself
/// (the birational map makes the two keys one), so it is wiped on drop, and
/// so is the digest it came from.
fn x25519_secret(seed: &[u8; ED25519_SEED_BYTES]) -> Zeroizing<[u8; 32]> {
    let mut digest = Sha512::digest(seed);
    let mut secret = Zeroizing::new([0u8; 32]);
    for (slot, byte) in secret.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    digest.as_mut_slice().zeroize();
    secret
}

/// An Ed25519 public key as its X25519 point. Takes a key only in its one
/// canonical spelling (decompression alone also reads a y at or past p), on
/// the curve, and of the prime order: no small-order key, and no key with a
/// small-order part, which would agree exactly as the key without it while
/// naming a different one.
///
/// The map to X25519 drops the sign bit, so `A` and `-A` share a point and a
/// secret: whoever holds `A`'s secret can name `-A` as the sender, and a seal
/// to `-A` opens with `A`'s secret. Neither matters, since a seal is taken
/// only from a key that is a leaf of the reader's group, and a device key's
/// negation is never one.
fn montgomery(key: &[u8; ED25519_PUBLIC_KEY_BYTES]) -> Result<MontgomeryPoint> {
    let point = CompressedEdwardsY(*key)
        .decompress()
        .ok_or_else(|| Error::invalid("a device key is not a point on the curve"))?;
    if point.compress().to_bytes() != *key {
        return Err(Error::invalid("a device key is not canonically encoded"));
    }
    if point.is_small_order() || !point.is_torsion_free() {
        return Err(Error::invalid("a device key is not of the prime order"));
    }
    Ok(point.to_montgomery())
}

/// `X25519(secret, point)`, refusing the all-zero output of a small-order
/// point. The agreement is wiped when it goes. The curve library takes the
/// scalar by value, so a copy of it lives on the stack for the call; and the
/// signing library keeps the device's seed for the client's life anyway, so
/// the wiping here narrows what a read of memory finds, and does not end it.
fn shared(point: MontgomeryPoint, secret: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let out = Zeroizing::new(point.mul_clamped(*secret).to_bytes());
    if out.iter().all(|byte| *byte == 0) {
        return Err(Error::invalid(
            "a device seal agreement is all zeros: a small-order point",
        ));
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const ADA: [u8; 32] = [0x11; 32];
    const BO: [u8; 32] = [0x22; 32];
    const CY: [u8; 32] = [0x33; 32];

    fn key(seed: &[u8; 32]) -> [u8; 32] {
        signing_key_public_key(seed).unwrap_or([0; 32])
    }

    #[test]
    fn a_seal_opens_for_its_device_and_names_its_sender() {
        let envelope = b"an envelope";
        let seal = device_seal(&ADA, &key(&BO), b"group-1", &[7; 32], envelope).unwrap();
        assert_eq!(seal.len(), DEVICE_SEAL_BYTES);
        let opened = device_seal_open(&BO, &seal, envelope).unwrap();
        assert_eq!(opened.sender_key, key(&ADA));
        assert_eq!(opened.group_id, b"group-1");
        assert_eq!(*opened.epoch_secret, [7; 32]);
    }

    /// A key no seal can be made for (the identity point is of small order)
    /// gets a filler of a seal's length and first byte, which opens for
    /// nobody.
    #[test]
    fn a_key_no_seal_can_be_made_for_gets_a_filler() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(!device_key_is_sealable(&identity));
        assert!(!device_key_is_sealable(&[0u8; 31]));
        assert!(device_key_is_sealable(&key(&BO)));
        assert!(device_seal(&ADA, &identity, b"g", &[7; 32], b"env").is_err());
        let filler = device_seal_filler().unwrap();
        assert_eq!(filler.len(), DEVICE_SEAL_BYTES);
        assert_eq!(filler[0], DEVICE_SEAL_VERSION);
        assert_ne!(filler, device_seal_filler().unwrap(), "random each time");
        assert!(device_seal_open(&BO, &filler, b"env").is_err());
    }

    #[test]
    fn a_seal_does_not_open_for_another_device_or_envelope() {
        let seal = device_seal(&ADA, &key(&BO), b"g", &[7; 32], b"one").unwrap();
        assert!(device_seal_open(&CY, &seal, b"one").is_err());
        assert!(device_seal_open(&BO, &seal, b"two").is_err());
        for at in [0, 1, 40, 100, DEVICE_SEAL_BYTES - 1] {
            let mut flipped = seal.clone();
            if let Some(byte) = flipped.get_mut(at) {
                *byte ^= 1;
            }
            assert!(
                device_seal_open(&BO, &flipped, b"one").is_err(),
                "byte {at}"
            );
        }
    }

    #[test]
    fn a_seal_naming_another_sender_does_not_open() {
        // Swap in Cy's key in the first layer, as the server could (it knows
        // Bo's key, so it can make the first layer): the second layer needs
        // the agreement between Cy's secret and Bo's, which it does not hold.
        let e = [0x44; 32];
        let honest =
            device_seal_with_ephemeral(&ADA, &key(&BO), b"g", &[7; 32], b"env", &e).unwrap();
        let e_public = MontgomeryPoint::mul_base_clamped(e).to_bytes();
        let shared_e = shared(montgomery(&key(&BO)).unwrap(), &e).unwrap();
        let k1 = sender_layer_key(&shared_e, &e_public, &key(&BO)).unwrap();
        let c1 = seal_aes(&k1, &key(&CY), &header(&e_public, &[])).unwrap();
        let mut forged = honest[..33].to_vec();
        forged.extend_from_slice(&c1);
        forged.extend_from_slice(&honest[81..]);
        assert_eq!(forged.len(), DEVICE_SEAL_BYTES);
        assert!(device_seal_open(&BO, &forged, b"env").is_err());
    }

    #[test]
    fn a_group_id_past_the_slot_is_refused() {
        let long = [b'g'; DEVICE_SEAL_MAX_GROUP_ID_BYTES + 1];
        assert!(device_seal(&ADA, &key(&BO), &long, &[7; 32], b"e").is_err());
        assert!(device_seal(&ADA, &key(&BO), b"", &[7; 32], b"e").is_err());
        let full = [b'g'; DEVICE_SEAL_MAX_GROUP_ID_BYTES];
        let seal = device_seal(&ADA, &key(&BO), &full, &[7; 32], b"e").unwrap();
        assert_eq!(device_seal_open(&BO, &seal, b"e").unwrap().group_id, full);
    }

    #[test]
    fn the_writer_is_off() {
        const { assert!(!DEVICE_SEAL_SENDS) };
    }
}
