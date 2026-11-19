// SPDX-License-Identifier: MIT
//! Approving a new device from one the person already has, and how the person
//! proves to each device that the other's key is the key of the device in
//! their hand.
//!
//! Pure functions, no state, no storage and no network: the bytes an approving
//! device signs over a new device's identity and how anyone checks them, and
//! the commit-then-reveal two-digit number the person confirms. A QR variant
//! is implemented below and reserved; no client uses it.
//!
//! ## Why the server cannot simply be told "yes"
//!
//! What the approving device signs, and seals the account key to, is a public
//! key the server handed it. A server that swapped the new device's key for
//! one it holds would get a genuine signature and the account key, and every
//! check in this file would pass over the wrong key. Nothing inside the
//! protocol can notice that, so the key has to cross once through the person
//! holding both devices.
//!
//! ## The number: commit, then reveal
//!
//! Two digits derived from the keys alone would be no defense: a server could
//! try a hundred keys of its own first. So the number also covers a fresh
//! random nonce from each side:
//!
//! 1. the approver draws a 32-byte nonce `nA` and publishes only its
//!    commitment, [`device_link_commitment`]`(nA)`;
//! 2. the new device, having seen the commitment, draws its own nonce `nN`
//!    and publishes it;
//! 3. the approver, having seen `nN`, reveals `nA`;
//! 4. both compute [`device_link_number`] over the new device's key, the
//!    approver's key, both nonces, and the commitment `nA` has to open.
//!
//! A server in the middle must fix the approver's view before it learns the
//! new device's (the commitment binds `nA` before `nN` exists), or the new
//! device's view before it learns the approver's (`nN` is published before
//! `nA` is revealed). Either way one side's number is a fresh uniform draw it
//! cannot steer, so a substituted key matches one time in a hundred per
//! exchange.
//!
//! The number is not symmetric: the new device's key always comes first, so
//! the two keys can never be swapped into an equal input. Two identical keys
//! are refused.
//!
//! ## Two numbers, one for each direction
//!
//! The new device's number, picked on the approver, tells the approver that
//! the key it is about to let in is right. It tells the new device nothing: a
//! server can run the exchange with the new device as an approver it invented
//! and seal it an account key of its own. So the approver also shows
//! [`device_link_approver_number`], over the same five values under another
//! domain, and the person picks it on the new device. Only then does the new
//! device accept an account key from that approver, and only from the key its
//! pairing bound. The two numbers are independent draws.
//!
//! ## One exchange per pairing
//!
//! A server knows the new device's nonce as soon as it answers, and its own
//! `nA` all along, so it knows the number the new device would show before
//! revealing anything. A new device that answered every fresh commitment
//! would let the server restart silently until the number matched.
//!
//! So the new device releases one nonce per pairing, and
//! [`device_link_waiter_step`] is its rule: the first exchange it answers
//! binds the pairing to that approver, that approver's key and that
//! commitment. The same three values continue the exchange; any other
//! commitment or key from that approver ends the pairing
//! ([`DeviceLinkWaiterStep::Interrupted`]), and the device says so and answers
//! nothing more until the person starts again; an exchange from any other
//! approver is never answered. The approver's key is bound because it is an
//! input to the number that the server supplies.
//!
//! A substituted key therefore matches one time in a hundred per pairing the
//! person starts by hand, and a pairing the server restarts is shown as
//! interrupted.
//!
//! ## The approver's rule: fix the new device's nonce before revealing
//!
//! The approver's number must be taken over the `nN` it saw before it revealed
//! `nA`. Otherwise a server that made the reveal's post fail could pick `nN`
//! afterwards, with every other input known, by an offline search of about
//! ten thousand hashes, and nothing would show.
//!
//! So [`device_link_approver_step`] is the approver's rule, one call per read
//! of the device list. The approver posts one commitment per prompt the
//! person opened, for the waiting row's key as it read it then. The first
//! read that lists a device nonce under that commitment fixes it, before the
//! reveal is posted. A failed reveal is posted again only while the listed
//! key, commitment and device nonce are exactly the fixed ones; any change is
//! [`DeviceLinkApproverStep::Interrupted`], and the approver closes approval
//! for that device until the person opens a new prompt. The number is derived
//! only over the fixed values.
//!
//! ## The approver signs its commitment
//!
//! The approver signs its commitment together with the waiting device's id
//! and key ([`sign_device_link_commitment`], domain
//! `peachy-device-link-commit-v2`), and the waiting device answers only an
//! exchange whose signature holds under the key its own device list gives for
//! that approver, over its own id and key ([`verify_device_link_commitment`]).
//! To stand in as an approver, a server must then list a device of its own,
//! which the person can see, and which the approver's number catches one time
//! in a hundred. The commitment the new device answers is also one made for
//! its real key.
//!
//! ## The waiting device's link key
//!
//! The approver seals the account key to the new device, and the box crosses
//! the server. Sealed to the new device's X25519 key alone, a box recorded
//! today opens for whoever later breaks that curve. So the new device draws a
//! 32-byte seed per pairing ([`generate_device_link_kem_seed`]) and posts the
//! X-Wing public key it derives ([`device_link_kem_public_key`], ML-KEM-768
//! combined with X25519) beside its nonce, signed under its own Ed25519 key
//! over its id, the commitment it answers, its nonce and the link key
//! ([`sign_device_link_kem`], domain `peachy-device-link-kem-v1`). The
//! approver checks that signature under the key it derives the number over
//! ([`verify_device_link_kem`]) when it fixes the device nonce, and seals to
//! that link key ([`crate::account_store::account_key_seal_hybrid`]). The
//! person's pick of the number vouches for the link key as it does for the
//! key it is signed under; the server can withhold a link key, which leaves
//! the approver nothing to seal to: the pairing fails, since the new device's
//! door refuses an X25519-only box unless its own test switch is on. It
//! cannot substitute one.
//!
//! ## The QR text
//!
//! [`device_link_qr`] is the new device's id, its whole 32-byte key and a
//! 32-byte link secret, as text a QR code could carry, and
//! [`device_link_qr_matches`] and [`device_link_qr_secret`] read it back. The
//! specification reserves this text and no client uses it: devices are
//! approved by the two-digit number alone (docs/identity.md §The QR
//! code). No door opens a box keyed with its secret: the new device's door
//! (`account_key_accept_hybrid`) refuses every version-2 box.
//!
//! ## The domains
//!
//! Every byte string is prefixed with an ASCII domain and a `0x00` separator,
//! so a signature or commitment over one statement never reads as one over
//! another.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::credential::ED25519_PUBLIC_KEY_BYTES;
use crate::error::{Error, Result};
use crate::identity::ED25519_SEED_BYTES;

/// The domain separator for the bytes an approving device signs.
pub const DEVICE_APPROVAL_DOMAIN: &str = "peachy-device-approval-v1";

/// The domain separator for the approver's commitment to its nonce.
pub const DEVICE_LINK_COMMIT_DOMAIN: &str = "peachy-device-link-commit-v1";

/// The domain separator for the approver's signature over its commitment, the
/// waiting device's id and the waiting device's key.
pub const DEVICE_LINK_COMMIT_SIGNATURE_DOMAIN: &str = "peachy-device-link-commit-v2";

/// The domain separator for the two-digit number.
pub const DEVICE_LINK_NUMBER_DOMAIN: &str = "peachy-device-link-v2";

/// The domain separator for the approver's two-digit number, the one the
/// person picks on the new device.
pub const DEVICE_LINK_APPROVER_NUMBER_DOMAIN: &str = "peachy-device-link-approver-v1";

/// The link secret a waiting device's QR code carries: 32 bytes.
pub const DEVICE_LINK_KEY_BYTES: usize = 32;

/// What every device-link QR code starts with.
pub const DEVICE_LINK_QR_PREFIX: &str = "peachy-link:";

/// An Ed25519 signature: 64 bytes, always.
pub const DEVICE_APPROVAL_SIGNATURE_BYTES: usize = 64;

/// Each side's nonce, and the commitment: 32 bytes.
pub const DEVICE_LINK_NONCE_BYTES: usize = 32;

/// The number is `0..100`, written as two digits.
const DEVICE_LINK_NUMBER_MODULUS: u64 = 100;

/// How many leading bytes of the digest the number is taken from. Sixty-four
/// bits into a hundred leaves a bias far below anything a person could see.
const DEVICE_LINK_NUMBER_HASH_BYTES: usize = 8;

/// The exact bytes an approving device signs to vouch for another device.
///
/// ```text
/// "peachy-device-approval-v1" || 0x00 || device_id || 0x00 || signing_key
/// ```
///
/// `device_id` is `devices.id` — the new device's row, not a label a person
/// chose — and `signing_key` is its raw 32-byte Ed25519 public key, the same
/// one `RegisterDevice` published. Both are in the statement because either
/// one alone would be forgeable into something else: a signature over the key
/// alone could be replayed onto any device row holding that key, and a
/// signature over the id alone would vouch for whatever key the server later
/// decided that row held.
///
/// Refuses an empty `device_id` and a `signing_key` that is not exactly 32
/// bytes. Neither is a rejection of an approval — they are a caller handing
/// over something that is not a device.
pub fn device_approval_statement(device_id: &str, signing_key: &[u8]) -> Result<Vec<u8>> {
    if device_id.is_empty() {
        return Err(Error::invalid("a device_id must not be empty"));
    }
    if signing_key.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(Error::invalid(format!(
            "a signing_key must be exactly {ED25519_PUBLIC_KEY_BYTES} bytes, got {}",
            signing_key.len()
        )));
    }

    let domain = DEVICE_APPROVAL_DOMAIN.as_bytes();
    let id = device_id.as_bytes();
    let mut statement = Vec::with_capacity(domain.len() + 1 + id.len() + 1 + signing_key.len());
    statement.extend_from_slice(domain);
    statement.push(0);
    statement.extend_from_slice(id);
    statement.push(0);
    statement.extend_from_slice(signing_key);
    Ok(statement)
}

/// Sign [`device_approval_statement`] with an approving device's own key.
///
/// `seed` is the 32-byte Ed25519 seed from the platform key store — the same
/// seed [`crate::identity::signing_key_public_key`] takes and the same one the
/// approving device's own credential is bound to. The signature is
/// deterministic (RFC 8032), which is what lets a golden fixture pin one.
///
/// Refuses a seed that is not exactly 32 bytes, and whatever
/// [`device_approval_statement`] refuses.
pub fn sign_device_approval(
    seed: &[u8],
    device_id: &str,
    signing_key: &[u8],
) -> Result<[u8; DEVICE_APPROVAL_SIGNATURE_BYTES]> {
    let seed: [u8; ED25519_SEED_BYTES] = seed.try_into().map_err(|_| {
        Error::invalid(format!(
            "a device signing key seed must be exactly {ED25519_SEED_BYTES} bytes, got {}",
            seed.len()
        ))
    })?;
    let statement = device_approval_statement(device_id, signing_key)?;
    Ok(SigningKey::from_bytes(&seed).sign(&statement).to_bytes())
}

/// Whether `signature` is a genuine approval of `(device_id, signing_key)` by
/// the holder of `approver_public_key`.
///
/// **A plain `bool`, never a `Result`, and deliberately.** A malformed
/// approver key, a signature of the wrong length, an empty device id and a
/// signature that simply does not check out all mean one thing to a caller:
/// this approval does not hold. A caller that could tell them apart would be
/// holding an oracle — feed it candidate keys and lengths and it answers
/// questions about the shape of a secret nobody offered it — and every caller
/// would then have to decide, at each call site, which failures are safe to
/// treat as "no". There is exactly one safe answer and it is this one.
///
/// Uses `verify_strict`, which refuses small-order and non-canonical public
/// keys. Those are the keys for which a single signature verifies under more
/// than one public key, and this whole flow is about being sure WHICH device
/// vouched.
pub fn verify_device_approval(
    approver_public_key: &[u8],
    device_id: &str,
    signing_key: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(key_bytes) = <[u8; ED25519_PUBLIC_KEY_BYTES]>::try_from(approver_public_key) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(signature_bytes) = <[u8; DEVICE_APPROVAL_SIGNATURE_BYTES]>::try_from(signature) else {
        return false;
    };
    let Ok(statement) = device_approval_statement(device_id, signing_key) else {
        return false;
    };
    verifying_key
        .verify_strict(&statement, &Signature::from_bytes(&signature_bytes))
        .is_ok()
}

fn exactly<'a>(bytes: &'a [u8], name: &str) -> Result<&'a [u8; 32]> {
    bytes.try_into().map_err(|_| {
        Error::invalid(format!(
            "a {name} must be exactly 32 bytes, got {}",
            bytes.len()
        ))
    })
}

/// The approver's commitment to its nonce: `SHA-256("peachy-device-link-commit-v1"
/// || 0x00 || nonce)`.
///
/// Published BEFORE the new device draws its own nonce, and opened only after
/// it has. The nonce is 32 bytes from the platform's CSPRNG, fresh for every
/// attempt, and never reused once revealed.
pub fn device_link_commitment(approver_nonce: &[u8]) -> Result<[u8; DEVICE_LINK_NONCE_BYTES]> {
    let nonce = exactly(approver_nonce, "approver_nonce")?;
    let mut hasher = Sha256::new();
    hasher.update(DEVICE_LINK_COMMIT_DOMAIN.as_bytes());
    hasher.update([0u8]);
    hasher.update(nonce);
    Ok(hasher.finalize().into())
}

/// The two-digit number the new device shows and the approver offers among
/// three, `"00"` to `"99"`.
///
/// Read the module header for why the nonces are there; the derivation is:
///
/// 1. every input must be exactly 32 bytes, and the two keys must differ;
/// 2. `approver_nonce` must open `approver_commitment` — otherwise this is an
///    error, never a number, because a number over a nonce the approver did
///    not commit to first is a number the server could have chosen;
/// 3. `h = SHA-256("peachy-device-link-v2" || 0x00 || new_device_key ||
///    approver_key || approver_commitment || device_nonce || approver_nonce)`;
/// 4. take `h[0..8]` as a big-endian u64, modulo 100, zero-padded to two
///    digits.
///
/// Both devices call this with the same five values when nobody rewrote any of
/// them: the new device with its own key, the approver's key as listed, the
/// commitment it was shown, its own nonce and the revealed one; the approver
/// with the waiting row's key, its own key, its own commitment, the nonce it
/// was shown and its own.
pub fn device_link_number(
    new_device_key: &[u8],
    approver_key: &[u8],
    approver_commitment: &[u8],
    device_nonce: &[u8],
    approver_nonce: &[u8],
) -> Result<String> {
    two_digits(
        DEVICE_LINK_NUMBER_DOMAIN,
        new_device_key,
        approver_key,
        approver_commitment,
        device_nonce,
        approver_nonce,
    )
}

/// The two-digit number the APPROVER shows and the new device offers among
/// three, `"00"` to `"99"`: [`device_link_number`]'s derivation over the same
/// five values in the same order, under
/// [`DEVICE_LINK_APPROVER_NUMBER_DOMAIN`] instead.
///
/// It is the other direction of the comparison (module header, "Two numbers,
/// one for each direction"): the person picks it on the new device, and the
/// new device then accepts an account key from that approver's key and no
/// other. The approver shows it only after the person picked the new device's
/// number on it.
pub fn device_link_approver_number(
    new_device_key: &[u8],
    approver_key: &[u8],
    approver_commitment: &[u8],
    device_nonce: &[u8],
    approver_nonce: &[u8],
) -> Result<String> {
    two_digits(
        DEVICE_LINK_APPROVER_NUMBER_DOMAIN,
        new_device_key,
        approver_key,
        approver_commitment,
        device_nonce,
        approver_nonce,
    )
}

fn two_digits(
    domain: &str,
    new_device_key: &[u8],
    approver_key: &[u8],
    approver_commitment: &[u8],
    device_nonce: &[u8],
    approver_nonce: &[u8],
) -> Result<String> {
    let new_device_key = exactly(new_device_key, "new_device_key")?;
    let approver_key = exactly(approver_key, "approver_key")?;
    let approver_commitment = exactly(approver_commitment, "approver_commitment")?;
    let device_nonce = exactly(device_nonce, "device_nonce")?;
    let approver_nonce = exactly(approver_nonce, "approver_nonce")?;
    if new_device_key == approver_key {
        return Err(Error::invalid(
            "a device cannot be compared with itself: the two keys are identical",
        ));
    }
    let opens: bool = device_link_commitment(approver_nonce)?[..]
        .ct_eq(&approver_commitment[..])
        .into();
    if !opens {
        return Err(Error::invalid(
            "the approver's nonce does not open its commitment",
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0u8]);
    hasher.update(new_device_key);
    hasher.update(approver_key);
    hasher.update(approver_commitment);
    hasher.update(device_nonce);
    hasher.update(approver_nonce);
    let digest = hasher.finalize();

    // Folded a byte at a time rather than sliced and indexed: this crate
    // denies the panicking accessors and an iterator cannot be off the end.
    let mut value: u64 = 0;
    for byte in digest.iter().take(DEVICE_LINK_NUMBER_HASH_BYTES) {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(format!("{:02}", value % DEVICE_LINK_NUMBER_MODULUS))
}

/// What the new (waiting) device does with one exchange on its own row,
/// given what its current pairing has already answered. Read the module
/// header's "One exchange per pairing" for why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceLinkWaiterStep {
    /// This pairing has answered nothing yet. Answering this commitment
    /// binds the pairing to this approver, its key and this commitment; a
    /// caller that cannot answer it now (the approver already revealed over
    /// another nonce) binds nothing.
    Answer = 0,
    /// The exchange this pairing is bound to. Send the SAME nonce again if the
    /// row lost it; once the approver reveals, the number is derived over the
    /// bound key and commitment.
    Continue = 1,
    /// Another approver's exchange, while this pairing is bound to one. Never
    /// answered: one nonce per pairing.
    Ignore = 2,
    /// The bound approver's commitment or key changed after this pairing
    /// answered. The pairing is over: show no number, answer nothing more, and
    /// tell the person, who starts again by hand.
    Interrupted = 3,
}

impl DeviceLinkWaiterStep {
    /// The name a fixture case and the wasm binding use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Answer => "answer",
            Self::Continue => "continue",
            Self::Ignore => "ignore",
            Self::Interrupted => "interrupted",
        }
    }
}

/// THE WAITING DEVICE'S RULE: one exchange per pairing.
///
/// `bound_*` is what the current pairing answered — all three empty when it
/// has answered nothing yet, all three set once it has; anything in between
/// is refused, because half a binding is a caller bug that would otherwise
/// read as "nothing bound" and answer again. The other three describe one
/// exchange on the waiting device's row: the approver's device id, the key
/// the device list gives for it, and its commitment.
///
/// - nothing bound: [`DeviceLinkWaiterStep::Answer`];
/// - the same approver, key and commitment: [`DeviceLinkWaiterStep::Continue`];
/// - the same approver with any other key or commitment:
///   [`DeviceLinkWaiterStep::Interrupted`];
/// - any other approver: [`DeviceLinkWaiterStep::Ignore`].
///
/// Refuses an empty approver id, and a key or commitment that is not 32
/// bytes, on either side. A caller treats a refusal of the OFFERED exchange as
/// "skip it": it binds nothing and answers nothing.
pub fn device_link_waiter_step(
    bound_approver_id: &str,
    bound_approver_key: &[u8],
    bound_commitment: &[u8],
    approver_id: &str,
    approver_key: &[u8],
    commitment: &[u8],
) -> Result<DeviceLinkWaiterStep> {
    if approver_id.is_empty() {
        return Err(Error::invalid("an approver_id must not be empty"));
    }
    let approver_key = exactly(approver_key, "approver_key")?;
    let commitment = exactly(commitment, "approver_commitment")?;

    let nothing_bound = bound_approver_id.is_empty()
        && bound_approver_key.is_empty()
        && bound_commitment.is_empty();
    if nothing_bound {
        return Ok(DeviceLinkWaiterStep::Answer);
    }
    if bound_approver_id.is_empty() {
        return Err(Error::invalid(
            "a bound pairing needs all three of bound_approver_id, bound_approver_key and \
             bound_commitment, or none",
        ));
    }
    let bound_key = exactly(bound_approver_key, "bound_approver_key")?;
    let bound_commitment = exactly(bound_commitment, "bound_commitment")?;

    if approver_id != bound_approver_id {
        return Ok(DeviceLinkWaiterStep::Ignore);
    }
    let same_commitment: bool = commitment[..].ct_eq(&bound_commitment[..]).into();
    if approver_key == bound_key && same_commitment {
        Ok(DeviceLinkWaiterStep::Continue)
    } else {
        Ok(DeviceLinkWaiterStep::Interrupted)
    }
}

/// The exact bytes an approver signs over the commitment it posts for one
/// waiting device (module header, "The approver signs its commitment").
///
/// ```text
/// "peachy-device-link-commit-v2" || 0x00 || pending_device_id || 0x00 ||
///     pending_key (32) || commitment (32)
/// ```
///
/// `pending_device_id` and `pending_key` are the waiting row's id and key as
/// the approver read them when the person opened the prompt; `commitment` is
/// [`device_link_commitment`] of the approver's nonce. Refuses an empty id and
/// a key or commitment that is not 32 bytes.
pub fn device_link_commitment_statement(
    pending_device_id: &str,
    pending_key: &[u8],
    commitment: &[u8],
) -> Result<Vec<u8>> {
    if pending_device_id.is_empty() {
        return Err(Error::invalid("a pending_device_id must not be empty"));
    }
    let pending_key = exactly(pending_key, "pending_key")?;
    let commitment = exactly(commitment, "approver_commitment")?;
    let domain = DEVICE_LINK_COMMIT_SIGNATURE_DOMAIN.as_bytes();
    let id = pending_device_id.as_bytes();
    let mut statement = Vec::with_capacity(domain.len() + 1 + id.len() + 1 + 64);
    statement.extend_from_slice(domain);
    statement.push(0);
    statement.extend_from_slice(id);
    statement.push(0);
    statement.extend_from_slice(pending_key);
    statement.extend_from_slice(commitment);
    Ok(statement)
}

/// Sign [`device_link_commitment_statement`] with the approving device's own
/// 32-byte seed. Deterministic (RFC 8032), so a fixture pins it.
pub fn sign_device_link_commitment(
    seed: &[u8],
    pending_device_id: &str,
    pending_key: &[u8],
    commitment: &[u8],
) -> Result<[u8; DEVICE_APPROVAL_SIGNATURE_BYTES]> {
    let seed: [u8; ED25519_SEED_BYTES] = seed.try_into().map_err(|_| {
        Error::invalid(format!(
            "a device signing key seed must be exactly {ED25519_SEED_BYTES} bytes, got {}",
            seed.len()
        ))
    })?;
    let statement = device_link_commitment_statement(pending_device_id, pending_key, commitment)?;
    Ok(SigningKey::from_bytes(&seed).sign(&statement).to_bytes())
}

/// Whether `signature` is the commitment signature of the device holding
/// `approver_key`, over this waiting device's id and key and this commitment.
///
/// The waiting device asks this of every exchange on its row, with the key of
/// the approver row its own device list gives (approved, not revoked,
/// `account_certified`), its own id and its own key. An exchange whose
/// signature does not hold is not an exchange with that approver about this
/// device: it is never answered, and it binds nothing. A plain `bool`, for the
/// reason [`verify_device_approval`] gives.
pub fn verify_device_link_commitment(
    approver_key: &[u8],
    pending_device_id: &str,
    pending_key: &[u8],
    commitment: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(key_bytes) = <[u8; ED25519_PUBLIC_KEY_BYTES]>::try_from(approver_key) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(signature_bytes) = <[u8; DEVICE_APPROVAL_SIGNATURE_BYTES]>::try_from(signature) else {
        return false;
    };
    let Ok(statement) =
        device_link_commitment_statement(pending_device_id, pending_key, commitment)
    else {
        return false;
    };
    verifying_key
        .verify_strict(&statement, &Signature::from_bytes(&signature_bytes))
        .is_ok()
}

// ---- The waiting device's post-quantum link key -------------------------------

/// The X-Wing key pair a waiting device draws for one pairing, from a 32-byte
/// seed (RFC 9180 `DeriveKeyPair`). Only the KEM is used: the account-key box
/// mixes an X-Wing shared secret into its key
/// ([`crate::account_store::account_key_seal_hybrid`]), and the AEAD and KDF
/// named here never run.
pub const DEVICE_LINK_KEM_HPKE: HpkeConfig = HpkeConfig(
    HpkeKemType::XWingKemDraft6,
    HpkeKdfType::HkdfSha256,
    HpkeAeadType::AesGcm256,
);

/// A link key's seed: 32 bytes.
pub const DEVICE_LINK_KEM_SEED_BYTES: usize = 32;

/// An X-Wing public key: ML-KEM-768's 1184 bytes and X25519's 32.
pub const DEVICE_LINK_KEM_PUBLIC_KEY_BYTES: usize = 1216;

/// The domain separator for the waiting device's signature over its link key.
pub const DEVICE_LINK_KEM_SIGNATURE_DOMAIN: &str = "peachy-device-link-kem-v1";

/// A fresh link-key seed from the platform CSPRNG, the one door every client
/// draws it through.
pub fn generate_device_link_kem_seed() -> Result<[u8; DEVICE_LINK_KEM_SEED_BYTES]> {
    let mut seed = [0u8; DEVICE_LINK_KEM_SEED_BYTES];
    getrandom::fill(&mut seed)
        .map_err(|err| Error::invalid(format!("the platform CSPRNG failed: {err}")))?;
    Ok(seed)
}

/// The X-Wing private key a link-key seed derives, for
/// [`crate::account_store`] to decapsulate with. Never leaves the core.
pub(crate) fn device_link_kem_private_key(seed: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    Ok(zeroize::Zeroizing::new(device_link_kem_pair(seed)?.0))
}

/// The X-Wing public key a link-key seed derives: what the waiting device
/// posts beside its nonce (`StepDeviceLink.device_link_key`). Deterministic,
/// so the fixture pins it.
pub fn device_link_kem_public_key(seed: &[u8]) -> Result<Vec<u8>> {
    Ok(device_link_kem_pair(seed)?.1)
}

fn device_link_kem_pair(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let seed = exactly(seed, "link key seed")?;
    let pair = RustCrypto::default()
        .derive_hpke_keypair(DEVICE_LINK_KEM_HPKE, seed)
        .map_err(|err| Error::invalid(format!("could not derive a link key: {err:?}")))?;
    if pair.public.len() != DEVICE_LINK_KEM_PUBLIC_KEY_BYTES {
        return Err(Error::invalid(format!(
            "a link key is {DEVICE_LINK_KEM_PUBLIC_KEY_BYTES} bytes, the KEM made {}",
            pair.public.len()
        )));
    }
    Ok((pair.private.to_vec(), pair.public))
}

/// The exact bytes a waiting device signs over the link key it posts with its
/// nonce:
///
/// ```text
/// "peachy-device-link-kem-v1" || 0x00 || pending_device_id || 0x00 ||
///     commitment (32) || device_nonce (32) || link_key (1216)
/// ```
///
/// Signed with the waiting device's own Ed25519 key, the key the two-digit
/// number checks, so an approver that verified the number knows the link key
/// is that device's for this exchange: the commitment and the nonce tie it to
/// the one exchange the pairing answered. Refuses an empty id and any field of
/// the wrong length.
pub fn device_link_kem_statement(
    pending_device_id: &str,
    commitment: &[u8],
    device_nonce: &[u8],
    link_key: &[u8],
) -> Result<Vec<u8>> {
    if pending_device_id.is_empty() {
        return Err(Error::invalid("a pending_device_id must not be empty"));
    }
    let commitment = exactly(commitment, "approver_commitment")?;
    let device_nonce = exactly(device_nonce, "device_nonce")?;
    if link_key.len() != DEVICE_LINK_KEM_PUBLIC_KEY_BYTES {
        return Err(Error::invalid(format!(
            "a link_key must be exactly {DEVICE_LINK_KEM_PUBLIC_KEY_BYTES} bytes, got {}",
            link_key.len()
        )));
    }
    let domain = DEVICE_LINK_KEM_SIGNATURE_DOMAIN.as_bytes();
    let id = pending_device_id.as_bytes();
    let mut statement = Vec::with_capacity(domain.len() + 1 + id.len() + 1 + 64 + link_key.len());
    statement.extend_from_slice(domain);
    statement.push(0);
    statement.extend_from_slice(id);
    statement.push(0);
    statement.extend_from_slice(commitment);
    statement.extend_from_slice(device_nonce);
    statement.extend_from_slice(link_key);
    Ok(statement)
}

/// Sign [`device_link_kem_statement`] with the waiting device's own 32-byte
/// seed. Deterministic (RFC 8032), so a fixture pins it.
pub fn sign_device_link_kem(
    seed: &[u8],
    pending_device_id: &str,
    commitment: &[u8],
    device_nonce: &[u8],
    link_key: &[u8],
) -> Result<[u8; DEVICE_APPROVAL_SIGNATURE_BYTES]> {
    let seed: [u8; ED25519_SEED_BYTES] = seed.try_into().map_err(|_| {
        Error::invalid(format!(
            "a device signing key seed must be exactly {ED25519_SEED_BYTES} bytes, got {}",
            seed.len()
        ))
    })?;
    let statement =
        device_link_kem_statement(pending_device_id, commitment, device_nonce, link_key)?;
    Ok(SigningKey::from_bytes(&seed).sign(&statement).to_bytes())
}

/// Whether `signature` is the waiting device's signature, under `pending_key`
/// (the key the approver derived the number over), on this link key for this
/// exchange. The approver seals the account key only when this holds;
/// otherwise it seals no box and the link fails. A plain `bool`, for the
/// reason [`verify_device_approval`] gives.
pub fn verify_device_link_kem(
    pending_key: &[u8],
    pending_device_id: &str,
    commitment: &[u8],
    device_nonce: &[u8],
    link_key: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(key_bytes) = <[u8; ED25519_PUBLIC_KEY_BYTES]>::try_from(pending_key) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(signature_bytes) = <[u8; DEVICE_APPROVAL_SIGNATURE_BYTES]>::try_from(signature) else {
        return false;
    };
    let Ok(statement) =
        device_link_kem_statement(pending_device_id, commitment, device_nonce, link_key)
    else {
        return false;
    };
    verifying_key
        .verify_strict(&statement, &Signature::from_bytes(&signature_bytes))
        .is_ok()
}

/// What the APPROVING device does next with its exchange for one waiting
/// device, given what it has fixed so far. Read the module header's "The
/// approver's rule" for why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceLinkApproverStep {
    /// Our commitment is not on the row and nothing is fixed yet: post the
    /// SAME commitment (and its signature) again. Never a fresh one: one
    /// commitment per prompt.
    Commit = 0,
    /// Our commitment is on the row and the waiting device has not answered.
    Wait = 1,
    /// Reveal our nonce. When nothing was fixed yet, the caller MUST first
    /// fix the listed device nonce as the bound one, and only then post; when
    /// one was fixed, this is a retry over exactly the inputs it fixed.
    Reveal = 2,
    /// Our reveal is on the row over the device nonce we fixed: derive the
    /// number over the pending key and the BOUND device nonce, and offer it.
    Show = 3,
    /// Something we fixed changed: the key, the commitment, the device nonce,
    /// or a reveal that is not ours. Show no number, close approval for this
    /// device on this approver like a wrong tap, and tell the person; only
    /// their tap starts a new prompt.
    Interrupted = 4,
}

impl DeviceLinkApproverStep {
    /// The name a fixture case and the wasm binding use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Wait => "wait",
            Self::Reveal => "reveal",
            Self::Show => "show",
            Self::Interrupted => "interrupted",
        }
    }
}

/// THE APPROVER'S RULE: fix the new device's nonce before revealing, and
/// treat any change after that as an interruption.
///
/// The caller holds, for one waiting device and one prompt the person opened:
/// - `pending_key`: the waiting row's key read when the prompt opened, the key
///   its commitment signature covers and the only key it will approve;
/// - `commitment`: its one commitment for this prompt;
/// - `bound_device_nonce`: empty until this function first answers
///   [`DeviceLinkApproverStep::Reveal`], then the device nonce that read
///   listed, kept for the rest of the prompt.
///
/// The `listed_*` values are what this read of the device list shows: the
/// waiting row's key, and this approver's exchange on it (all three empty when
/// there is none).
///
/// - the listed key differs from `pending_key`: `Interrupted`;
/// - our commitment is not listed: `Commit` while nothing is fixed,
///   `Interrupted` once a device nonce is;
/// - a listed approver nonce that does not open our commitment, or one that
///   does while nothing is fixed: `Interrupted`;
/// - nothing fixed: `Wait` until a 32-byte device nonce is listed, then
///   `Reveal` (fix that nonce first);
/// - fixed: a different listed device nonce is `Interrupted`; the same one is
///   `Reveal` until our reveal is listed, then `Show`.
///
/// Refuses a `pending_key` or `commitment` that is not 32 bytes and a
/// `bound_device_nonce` that is neither empty nor 32 bytes: those are the
/// caller's own state, and a malformed one is a bug.
pub fn device_link_approver_step(
    pending_key: &[u8],
    commitment: &[u8],
    bound_device_nonce: &[u8],
    listed_key: &[u8],
    listed_commitment: &[u8],
    listed_device_nonce: &[u8],
    listed_approver_nonce: &[u8],
) -> Result<DeviceLinkApproverStep> {
    let pending_key = exactly(pending_key, "pending_key")?;
    let commitment = exactly(commitment, "approver_commitment")?;
    let bound = match bound_device_nonce.len() {
        0 => None,
        _ => Some(exactly(bound_device_nonce, "bound_device_nonce")?),
    };

    if listed_key != pending_key.as_slice() {
        return Ok(DeviceLinkApproverStep::Interrupted);
    }
    if listed_commitment != commitment.as_slice() {
        return Ok(match bound {
            None => DeviceLinkApproverStep::Commit,
            Some(_) => DeviceLinkApproverStep::Interrupted,
        });
    }
    let revealed = !listed_approver_nonce.is_empty();
    if revealed {
        let ours = listed_approver_nonce.len() == DEVICE_LINK_NONCE_BYTES
            && bool::from(
                device_link_commitment(listed_approver_nonce)?[..].ct_eq(&commitment[..]),
            );
        if !ours {
            return Ok(DeviceLinkApproverStep::Interrupted);
        }
    }
    match bound {
        None => {
            if revealed {
                // A reveal of ours this prompt never fixed a nonce for.
                Ok(DeviceLinkApproverStep::Interrupted)
            } else if listed_device_nonce.len() == DEVICE_LINK_NONCE_BYTES {
                Ok(DeviceLinkApproverStep::Reveal)
            } else {
                Ok(DeviceLinkApproverStep::Wait)
            }
        }
        Some(bound) => {
            if listed_device_nonce != bound.as_slice() {
                Ok(DeviceLinkApproverStep::Interrupted)
            } else if revealed {
                Ok(DeviceLinkApproverStep::Show)
            } else {
                Ok(DeviceLinkApproverStep::Reveal)
            }
        }
    }
}

/// The text the new device's QR code carries:
/// `"peachy-link:" || device_id || "/" || hex(signing_key) || "/" ||
/// hex(link_secret)`, hex in lower case.
///
/// Reserved (module header, "The QR text"): no client uses it. The whole
/// key, not a hash of it: a reader compares it with the waiting row's key
/// byte for byte, and a shorter fingerprint would only be a thing a server
/// could grind. The link secret is 32 bytes drawn from a CSPRNG and shown
/// only on the screen. Refuses an empty
/// `device_id`, one containing `/` or anything but printable ASCII, and a key
/// or secret that is not 32 bytes.
pub fn device_link_qr(device_id: &str, signing_key: &[u8], link_secret: &[u8]) -> Result<String> {
    if device_id.is_empty()
        || device_id.contains('/')
        || !device_id.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(Error::invalid(
            "a device_id must be non-empty printable ASCII without '/'",
        ));
    }
    let key = exactly(signing_key, "signing_key")?;
    let secret = exactly(link_secret, "link_secret")?;
    let mut text =
        String::with_capacity(DEVICE_LINK_QR_PREFIX.len() + device_id.len() + 2 + 2 * 64);
    text.push_str(DEVICE_LINK_QR_PREFIX);
    text.push_str(device_id);
    text.push('/');
    push_hex(&mut text, key);
    text.push('/');
    push_hex(&mut text, secret);
    Ok(text)
}

fn push_hex(text: &mut String, bytes: &[u8]) {
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
}

/// The link secret of a scanned QR code, when it names exactly this waiting
/// device and this key; `None` otherwise.
///
/// Reserved, as the QR text is (§The QR text): no client calls it, and no
/// door opens a box keyed with what it returns. Surrounding whitespace is
/// ignored (scanners add it); nothing else is: the secret must be 64
/// lower-case hex digits, the form [`device_link_qr`] writes.
pub fn device_link_qr_secret(
    scanned: &str,
    device_id: &str,
    signing_key: &[u8],
) -> Option<[u8; DEVICE_LINK_KEY_BYTES]> {
    let rest = scanned.trim().strip_prefix(DEVICE_LINK_QR_PREFIX)?;
    let (id, rest) = rest.split_once('/')?;
    let (key_hex, secret_hex) = rest.split_once('/')?;
    if id.is_empty() || id != device_id {
        return None;
    }
    let key: &[u8; 32] = signing_key.try_into().ok()?;
    if lower_hex(key_hex)? != *key {
        return None;
    }
    lower_hex(secret_hex)
}

/// Exactly 64 lower-case hex digits, as 32 bytes.
fn lower_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let digit = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 32];
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (slot, [hi, lo]) in out.iter_mut().zip(pairs) {
        *slot = (digit(*hi)? << 4) | digit(*lo)?;
    }
    Some(out)
}

/// Whether a scanned QR code names exactly this waiting device and this key
/// (and carries a well-formed link secret).
///
/// A plain `bool`, for the reason [`verify_device_approval`] gives: a code
/// from some other app, a key of the wrong length and a different device all
/// mean one thing to the approver, which is "not this one". Surrounding
/// whitespace is ignored (scanners add it); nothing else is.
pub fn device_link_qr_matches(scanned: &str, device_id: &str, signing_key: &[u8]) -> bool {
    device_link_qr_secret(scanned, device_id, signing_key).is_some()
}

#[cfg(test)]
// The crate denies `expect` and `unwrap` for the LIBRARY. A test that cannot
// proceed should stop on the line that failed.
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const ADA_SEED: [u8; 32] = [0x11; 32];
    const LAPTOP_KEY: [u8; 32] = [0x22; 32];
    const OTHER_KEY: [u8; 32] = [0x33; 32];

    fn ada_public() -> [u8; 32] {
        crate::identity::signing_key_public_key(&ADA_SEED).expect("a 32-byte seed has a public key")
    }

    #[test]
    fn the_statement_is_domain_id_key_with_nul_separators() {
        let statement = device_approval_statement("device-ada-laptop", &LAPTOP_KEY)
            .expect("an ordinary statement");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"peachy-device-approval-v1");
        expected.push(0);
        expected.extend_from_slice(b"device-ada-laptop");
        expected.push(0);
        expected.extend_from_slice(&LAPTOP_KEY);
        assert_eq!(statement, expected);
    }

    #[test]
    fn the_statement_names_the_field_and_the_size_it_wanted() {
        let err = device_approval_statement("device-ada-laptop", &[0x22; 31])
            .expect_err("a short key is refused");
        assert!(err.to_string().contains("signing_key"), "{err}");
        assert!(err.to_string().contains("32 bytes"), "{err}");

        let err =
            device_approval_statement("", &LAPTOP_KEY).expect_err("an empty device id is refused");
        assert!(err.to_string().contains("device_id"), "{err}");
    }

    #[test]
    fn a_signature_round_trips_and_is_bound_to_every_part_of_the_statement() {
        let signature = sign_device_approval(&ADA_SEED, "device-ada-laptop", &LAPTOP_KEY)
            .expect("ada signs the laptop");
        let approver = ada_public();

        assert!(verify_device_approval(
            &approver,
            "device-ada-laptop",
            &LAPTOP_KEY,
            &signature
        ));
        // Every input is covered, so changing any one of them breaks it.
        assert!(!verify_device_approval(
            &approver,
            "device-ada-phone",
            &LAPTOP_KEY,
            &signature
        ));
        assert!(!verify_device_approval(
            &approver,
            "device-ada-laptop",
            &OTHER_KEY,
            &signature
        ));
        assert!(!verify_device_approval(
            &[0x44; 32],
            "device-ada-laptop",
            &LAPTOP_KEY,
            &signature
        ));
    }

    #[test]
    fn verification_answers_false_rather_than_failing() {
        // The oracle question. None of these is a Result, and none of them is
        // distinguishable from a signature that simply did not check out.
        let signature = sign_device_approval(&ADA_SEED, "device-ada-laptop", &LAPTOP_KEY)
            .expect("ada signs the laptop");
        assert!(!verify_device_approval(
            &[],
            "device-ada-laptop",
            &LAPTOP_KEY,
            &signature
        ));
        assert!(!verify_device_approval(
            &[0u8; 31],
            "device-ada-laptop",
            &LAPTOP_KEY,
            &signature
        ));
        assert!(!verify_device_approval(
            &ada_public(),
            "device-ada-laptop",
            &LAPTOP_KEY,
            &signature[..63]
        ));
        assert!(!verify_device_approval(
            &ada_public(),
            "",
            &LAPTOP_KEY,
            &signature
        ));
        assert!(!verify_device_approval(
            &ada_public(),
            "device-ada-laptop",
            &LAPTOP_KEY[..31],
            &signature
        ));
    }

    const NONCE_N: [u8; 32] = [0x55; 32];
    const NONCE_A: [u8; 32] = [0x66; 32];

    fn number(new_key: &[u8], approver: &[u8], n: &[u8], a: &[u8]) -> Result<String> {
        let commitment = device_link_commitment(a).expect("a 32-byte nonce commits");
        device_link_number(new_key, approver, &commitment, n, a)
    }

    #[test]
    fn the_number_is_two_digits() {
        let n = number(&LAPTOP_KEY, &OTHER_KEY, &NONCE_N, &NONCE_A).expect("an ordinary number");
        assert_eq!(n.len(), 2);
        assert!(n.chars().all(|c| c.is_ascii_digit()), "{n}");
    }

    #[test]
    fn the_number_covers_every_input() {
        let base = number(&LAPTOP_KEY, &OTHER_KEY, &NONCE_N, &NONCE_A).expect("base");
        // Two digits collide one time in a hundred, so "covers" is asserted
        // over many variations rather than one: some must differ.
        let mut differs = 0;
        for byte in 0u8..32 {
            let other = [byte; 32];
            if other == LAPTOP_KEY || other == OTHER_KEY {
                continue;
            }
            for changed in [
                number(&other, &OTHER_KEY, &NONCE_N, &NONCE_A),
                number(&LAPTOP_KEY, &other, &NONCE_N, &NONCE_A),
                number(&LAPTOP_KEY, &OTHER_KEY, &other, &NONCE_A),
                number(&LAPTOP_KEY, &OTHER_KEY, &NONCE_N, &other),
            ] {
                if changed.expect("a number") != base {
                    differs += 1;
                }
            }
        }
        assert!(differs > 100, "only {differs} variations moved the number");
    }

    #[test]
    fn the_number_is_not_symmetric_in_the_keys() {
        // Each side knows its role; swapping them is a different question.
        let mut differs = 0;
        for byte in 0u8..16 {
            let nonce = [byte; 32];
            let one = number(&LAPTOP_KEY, &OTHER_KEY, &nonce, &NONCE_A).expect("one");
            let other = number(&OTHER_KEY, &LAPTOP_KEY, &nonce, &NONCE_A).expect("other");
            if one != other {
                differs += 1;
            }
        }
        assert!(differs > 0);
    }

    #[test]
    fn a_nonce_that_does_not_open_the_commitment_is_refused() {
        let commitment = device_link_commitment(&NONCE_A).expect("commits");
        let err = device_link_number(&LAPTOP_KEY, &OTHER_KEY, &commitment, &NONCE_N, &NONCE_N)
            .expect_err("refused");
        assert!(err.to_string().contains("commitment"), "{err}");
    }

    #[test]
    fn one_key_against_itself_is_refused_rather_than_answered() {
        let err = number(&LAPTOP_KEY, &LAPTOP_KEY, &NONCE_N, &NONCE_A).expect_err("refused");
        assert!(err.to_string().contains("itself"), "{err}");
        let err = number(&[0x22; 31], &OTHER_KEY, &NONCE_N, &NONCE_A).expect_err("short");
        assert!(err.to_string().contains("new_device_key"), "{err}");
        let err = number(&LAPTOP_KEY, &OTHER_KEY, &[0x55; 33], &NONCE_A).expect_err("long");
        assert!(err.to_string().contains("device_nonce"), "{err}");
    }

    const APPROVER_X: &str = "device-ada-phone";
    const APPROVER_Y: &str = "device-ada-tablet";

    /// The waiting device's state, as every client keeps it: what its pairing
    /// is bound to, whether it was interrupted, and how many nonces it has
    /// released. Driven only through `device_link_waiter_step`.
    #[derive(Default)]
    struct Pairing {
        bound: Option<(String, [u8; 32], [u8; 32])>,
        interrupted: bool,
        nonces_released: usize,
        shown: Option<String>,
    }

    impl Pairing {
        fn see(
            &mut self,
            approver: &str,
            key: [u8; 32],
            commitment: [u8; 32],
        ) -> DeviceLinkWaiterStep {
            let (id, bound_key, bound_commitment) = match &self.bound {
                Some((id, k, c)) => (id.as_str(), &k[..], &c[..]),
                None => ("", &[][..], &[][..]),
            };
            let step = device_link_waiter_step(
                id,
                bound_key,
                bound_commitment,
                approver,
                &key,
                &commitment,
            )
            .expect("well-formed exchange");
            if self.interrupted {
                return step;
            }
            match step {
                DeviceLinkWaiterStep::Answer => {
                    self.bound = Some((approver.to_string(), key, commitment));
                    self.nonces_released += 1;
                }
                DeviceLinkWaiterStep::Interrupted => {
                    self.interrupted = true;
                    self.shown = None;
                }
                DeviceLinkWaiterStep::Continue | DeviceLinkWaiterStep::Ignore => {}
            }
            step
        }
    }

    #[test]
    fn the_first_exchange_binds_the_pairing_and_the_same_one_continues() {
        let c1 = device_link_commitment(&NONCE_A).expect("commits");
        let mut pairing = Pairing::default();
        assert_eq!(
            pairing.see(APPROVER_X, OTHER_KEY, c1),
            DeviceLinkWaiterStep::Answer
        );
        assert_eq!(
            pairing.see(APPROVER_X, OTHER_KEY, c1),
            DeviceLinkWaiterStep::Continue
        );
        assert_eq!(pairing.nonces_released, 1);
    }

    /// THE REGRESSION for restart grinding: a server that knows the waiting
    /// device's number before revealing must not be able to start the
    /// exchange over and get a second nonce. Once a number is on screen, a new
    /// commitment from the same approver ends the pairing, a new key for that
    /// approver ends it, and a commitment from another approver is never
    /// answered.
    #[test]
    fn a_second_exchange_after_a_shown_number_is_refused() {
        let c1 = device_link_commitment(&NONCE_A).expect("commits");
        let mut pairing = Pairing::default();
        assert_eq!(
            pairing.see(APPROVER_X, OTHER_KEY, c1),
            DeviceLinkWaiterStep::Answer
        );
        pairing.shown = Some(
            device_link_number(&LAPTOP_KEY, &OTHER_KEY, &c1, &NONCE_N, &NONCE_A).expect("a number"),
        );

        // Another approver, listed by the server: not answered.
        let c2 = device_link_commitment(&[0x77; 32]).expect("commits");
        assert_eq!(
            pairing.see(APPROVER_Y, [0x44; 32], c2),
            DeviceLinkWaiterStep::Ignore
        );
        assert!(
            pairing.shown.is_some(),
            "an ignored exchange changes nothing"
        );

        // The same approver, restarted: the pairing is over, and visibly.
        assert_eq!(
            pairing.see(APPROVER_X, OTHER_KEY, c2),
            DeviceLinkWaiterStep::Interrupted
        );
        assert!(pairing.interrupted);
        assert_eq!(
            pairing.shown, None,
            "an interrupted pairing shows no number"
        );

        // And nothing after it releases another nonce, whatever comes.
        for byte in 0u8..=255 {
            let commitment = device_link_commitment(&[byte; 32]).expect("commits");
            pairing.see(APPROVER_X, OTHER_KEY, commitment);
            pairing.see(APPROVER_Y, [0x44; 32], commitment);
        }
        assert_eq!(pairing.nonces_released, 1, "one nonce per pairing");
    }

    #[test]
    fn a_new_key_for_the_bound_approver_ends_the_pairing() {
        // The approver's key comes off the server's device list. Read again
        // after the reveal it would be an input the server picks with every
        // other input known; bound at the answer, a change is an interruption.
        let c1 = device_link_commitment(&NONCE_A).expect("commits");
        let mut pairing = Pairing::default();
        pairing.see(APPROVER_X, OTHER_KEY, c1);
        assert_eq!(
            pairing.see(APPROVER_X, [0x44; 32], c1),
            DeviceLinkWaiterStep::Interrupted
        );
    }

    #[test]
    fn the_first_of_several_approvers_binds_and_the_rest_are_ignored() {
        let mut pairing = Pairing::default();
        let mut steps = Vec::new();
        for byte in 1u8..=5 {
            let commitment = device_link_commitment(&[byte; 32]).expect("commits");
            steps.push(pairing.see(&format!("approver-{byte}"), [byte; 32], commitment));
        }
        assert_eq!(steps.first(), Some(&DeviceLinkWaiterStep::Answer));
        assert!(
            steps
                .iter()
                .skip(1)
                .all(|s| *s == DeviceLinkWaiterStep::Ignore),
            "{steps:?}"
        );
        assert_eq!(pairing.nonces_released, 1);
    }

    #[test]
    fn the_waiter_step_refuses_half_a_binding_and_malformed_exchanges() {
        let c1 = device_link_commitment(&NONCE_A).expect("commits");
        let err = device_link_waiter_step("", &[], &[], "", &OTHER_KEY, &c1).expect_err("empty id");
        assert!(err.to_string().contains("approver_id"), "{err}");
        let err = device_link_waiter_step("", &[], &[], APPROVER_X, &OTHER_KEY[..31], &c1)
            .expect_err("short");
        assert!(err.to_string().contains("approver_key"), "{err}");
        let err = device_link_waiter_step("", &[], &[], APPROVER_X, &OTHER_KEY, &c1[..31])
            .expect_err("short commitment");
        assert!(err.to_string().contains("approver_commitment"), "{err}");
        // Half a binding never reads as "nothing bound".
        let err = device_link_waiter_step("", &OTHER_KEY, &c1, APPROVER_X, &OTHER_KEY, &c1)
            .expect_err("no id");
        assert!(err.to_string().contains("all three"), "{err}");
        let err = device_link_waiter_step(APPROVER_X, &[], &c1, APPROVER_X, &OTHER_KEY, &c1)
            .expect_err("no key");
        assert!(err.to_string().contains("bound_approver_key"), "{err}");
        let err = device_link_waiter_step(APPROVER_X, &OTHER_KEY, &[], APPROVER_X, &OTHER_KEY, &c1)
            .expect_err("no commitment");
        assert!(err.to_string().contains("bound_commitment"), "{err}");
    }

    const SECRET: [u8; 32] = [0x5e; 32];

    #[test]
    fn the_qr_code_carries_the_whole_key_and_the_secret_and_matches_only_them() {
        let text =
            device_link_qr("device-ada-laptop", &LAPTOP_KEY, &SECRET).expect("an ordinary code");
        assert_eq!(
            text,
            format!(
                "peachy-link:device-ada-laptop/{}/{}",
                "22".repeat(32),
                "5e".repeat(32)
            )
        );
        assert!(device_link_qr_matches(
            &text,
            "device-ada-laptop",
            &LAPTOP_KEY
        ));
        assert_eq!(
            device_link_qr_secret(&format!(" {text}\n"), "device-ada-laptop", &LAPTOP_KEY),
            Some(SECRET)
        );
        assert!(!device_link_qr_matches(
            &text,
            "device-ada-phone",
            &LAPTOP_KEY
        ));
        assert!(!device_link_qr_matches(
            &text,
            "device-ada-laptop",
            &OTHER_KEY
        ));
        assert!(!device_link_qr_matches(
            &text.to_uppercase(),
            "device-ada-laptop",
            &LAPTOP_KEY
        ));
        assert!(!device_link_qr_matches(
            &text,
            "device-ada-laptop",
            &LAPTOP_KEY[..31]
        ));
        // A code without a secret, or with a short one, is not a link code.
        let bare = format!("peachy-link:device-ada-laptop/{}", "22".repeat(32));
        assert!(!device_link_qr_matches(
            &bare,
            "device-ada-laptop",
            &LAPTOP_KEY
        ));
        assert!(!device_link_qr_matches(
            &format!("{bare}/{}", "5e".repeat(31)),
            "device-ada-laptop",
            &LAPTOP_KEY
        ));
        assert!(!device_link_qr_matches(
            &format!("{text}/"),
            "device-ada-laptop",
            &LAPTOP_KEY
        ));
        assert!(device_link_qr("a/b", &LAPTOP_KEY, &SECRET).is_err());
        assert!(device_link_qr("", &LAPTOP_KEY, &SECRET).is_err());
        let err = device_link_qr("device-ada-laptop", &LAPTOP_KEY, &SECRET[..31])
            .expect_err("a short secret");
        assert!(err.to_string().contains("link_secret"), "{err}");
    }

    #[test]
    fn the_approver_number_is_a_second_independent_draw() {
        let commitment = device_link_commitment(&NONCE_A).expect("commits");
        let mut same = 0;
        for byte in 0u8..=255 {
            let device_nonce = [byte; 32];
            let one = device_link_number(
                &LAPTOP_KEY,
                &OTHER_KEY,
                &commitment,
                &device_nonce,
                &NONCE_A,
            )
            .expect("a number");
            let two = device_link_approver_number(
                &LAPTOP_KEY,
                &OTHER_KEY,
                &commitment,
                &device_nonce,
                &NONCE_A,
            )
            .expect("a number");
            assert_eq!(two.len(), 2);
            if one == two {
                same += 1;
            }
        }
        assert!(same < 16, "the two numbers agree too often: {same} of 256");
        // The same refusals as the first number.
        assert!(device_link_approver_number(
            &LAPTOP_KEY,
            &OTHER_KEY,
            &commitment,
            &NONCE_N,
            &[0x77; 32]
        )
        .is_err());
        assert!(device_link_approver_number(
            &LAPTOP_KEY,
            &LAPTOP_KEY,
            &commitment,
            &NONCE_N,
            &NONCE_A
        )
        .is_err());
    }

    #[test]
    fn a_link_key_is_an_x_wing_key_derived_from_its_seed() {
        let a = device_link_kem_public_key(&[0x5a; 32]).expect("a link key");
        assert_eq!(a.len(), DEVICE_LINK_KEM_PUBLIC_KEY_BYTES);
        assert_eq!(a, device_link_kem_public_key(&[0x5a; 32]).expect("again"));
        assert_ne!(a, device_link_kem_public_key(&[0x5b; 32]).expect("another"));
        assert!(device_link_kem_public_key(&[0x5a; 31]).is_err());
        let fresh = generate_device_link_kem_seed().expect("a seed");
        assert_ne!(
            fresh,
            generate_device_link_kem_seed().expect("another seed")
        );
    }

    #[test]
    fn the_link_key_signature_holds_only_for_its_device_exchange_and_key() {
        let link_key = device_link_kem_public_key(&[0x5a; 32]).expect("a link key");
        let commitment = [0x44u8; 32];
        let nonce = [0x55u8; 32];
        let id = "device-ada-laptop";
        let signature =
            sign_device_link_kem(&ADA_SEED, id, &commitment, &nonce, &link_key).expect("signs");
        let statement =
            device_link_kem_statement(id, &commitment, &nonce, &link_key).expect("a statement");
        assert!(statement.starts_with(b"peachy-device-link-kem-v1\0device-ada-laptop\0"));
        assert_eq!(statement.len(), 25 + 1 + id.len() + 1 + 64 + 1216);
        assert!(verify_device_link_kem(
            &ada_public(),
            id,
            &commitment,
            &nonce,
            &link_key,
            &signature
        ));

        // Another signer, row, exchange, nonce or link key: no.
        let other_link = device_link_kem_public_key(&[0x5b; 32]).expect("another link key");
        assert!(!verify_device_link_kem(
            &LAPTOP_KEY,
            id,
            &commitment,
            &nonce,
            &link_key,
            &signature
        ));
        assert!(!verify_device_link_kem(
            &ada_public(),
            "device-ada-phone",
            &commitment,
            &nonce,
            &link_key,
            &signature
        ));
        assert!(!verify_device_link_kem(
            &ada_public(),
            id,
            &[0x45; 32],
            &nonce,
            &link_key,
            &signature
        ));
        assert!(!verify_device_link_kem(
            &ada_public(),
            id,
            &commitment,
            &[0x56; 32],
            &link_key,
            &signature
        ));
        assert!(!verify_device_link_kem(
            &ada_public(),
            id,
            &commitment,
            &nonce,
            &other_link,
            &signature
        ));
        // Malformed inputs are a plain no.
        assert!(!verify_device_link_kem(
            &ada_public(),
            id,
            &commitment,
            &nonce,
            &link_key[..1215],
            &signature
        ));
        assert!(!verify_device_link_kem(
            &ada_public(),
            id,
            &commitment,
            &nonce,
            &link_key,
            &signature[..63]
        ));
        // The commitment signature over the same exchange never reads as one.
        let commit_sig =
            sign_device_link_commitment(&ADA_SEED, id, &LAPTOP_KEY, &commitment).expect("signs");
        assert!(!verify_device_link_kem(
            &ada_public(),
            id,
            &commitment,
            &nonce,
            &link_key,
            &commit_sig
        ));
    }
}
