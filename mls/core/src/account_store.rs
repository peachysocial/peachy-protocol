// SPDX-License-Identifier: MIT
//! The encrypted account store: what a person's account remembers — contacts,
//! chat settings, account preferences — kept on the server as values only the
//! person's own devices can read, and, with the PIN, whoever opens the PIN
//! vault's copy of the account key (docs/account-store.md §Security
//! considerations).
//!
//! Pure functions, no state, no storage and no network, in the same shape as
//! [`crate::device_link`]. Two jobs:
//!
//! 1. **Sealing a record.** Every record, and the one manifest that lists them,
//!    is sealed under a key derived from ONE 32-byte account key and the
//!    record's own 16-byte id ([`store_seal`] / [`store_open`]).
//! 2. **Carrying the account key to a new device.** When a device the person
//!    already has approves a new one, it seals the account key to the new
//!    device's keys in a box ([`account_key_seal_hybrid`]; the 93-byte
//!    [`account_key_seal`] for a server-run device's approvals: test servers
//!    and the store-review login), which the
//!    server stores and hands over and cannot open, and the new device takes it only through
//!    [`account_key_accept_hybrid`].
//!
//! Nothing here touches a group. The account store is not an MLS feature and
//! nothing in `group.rs` knows it exists; it lives in this crate only because
//! this is the one place every client already shares a byte-exact
//! implementation of anything (docs/mls-core.md §Account store).
//!
//! ## A record
//!
//! ```text
//! k(id)  = HKDF-SHA256(ikm = account_key, salt = <empty>,
//!                      info = "peachy store v1" || 0x00 || id, L = 32)
//! value  = 0x01 || nonce(12) || AES-256-GCM(k(id), nonce, pad(plaintext), aad = id)
//! pad(p) = p || 0x80 || 0x00 * n      (to the next multiple of 256 bytes)
//! ```
//!
//! A key PER ID, and the id is the AEAD's associated data as well. Either one
//! alone would do the job it is there for — the server cannot hand a device
//! record A's value under record B's id and have it open — and both together
//! cost nothing. The padding is there because the length of a sealed value is
//! the one thing about it the server can read: a contact's record and a chat's
//! record differ in size, and 256-byte buckets make "a record" the most it can
//! tell.
//!
//! **The manifest is sealed exactly the same way**, under the reserved id
//! [`MANIFEST_ID`] (sixteen zero bytes), which is why a record id may never be
//! all zeros. There is no second format to get wrong.
//!
//! ## Why record ids are random
//!
//! A record's id is sixteen random bytes minted by a client, never anything
//! derived from what the record is about. An id derived from the subject — a
//! hash of a contact's actor id, say — would be the same every time that
//! contact's record was rewritten, and the server, which sees every id, would
//! learn which writes touched the same person and how often. Random ids, and a
//! NEW random id whenever a subject's record changes (the old one deleted in
//! the same write), leave it a set of opaque names that churn. Which id means
//! which contact is written only in the manifest, which it cannot read. This
//! module does not mint ids — a client does, from its own CSPRNG — but it
//! refuses any id that is not exactly 16 bytes, so an id cannot quietly become
//! a string somebody chose.
//!
//! ## The account-key box, and why it authenticates the SENDER
//!
//! ```text
//! a   = clamp(SHA-512(approver_seed)[0..32])       the approver's Ed25519 seed, as X25519
//! R   = Montgomery(recipient_signing_key)          the new device's Ed25519 public key, as X25519
//! e   = 32 fresh random bytes;  E = X25519(e, 9)
//! ikm = X25519(e, R) || X25519(a, R)
//! key = HKDF-SHA256(ikm, salt = <empty>, info = "peachy account key v1" || 0x00
//!                   || A_ed || recipient_signing_key || device_id, L = 32)
//! box = 0x01 || E || nonce(12) || AES-256-GCM(key, nonce, account_key, aad = E)   = 93 bytes
//! ```
//!
//! The first half of the input keying material is ordinary ephemeral-static
//! Diffie-Hellman: only the new device can compute `X25519(e, R)`, so only the
//! new device can open the box. That alone would be ENCRYPTION and nothing
//! more — anybody who knows the new device's public key, the server included,
//! could make a box of that shape around an account key of their own choosing,
//! and the new device would open it and start writing the person's contacts
//! into a store the server holds the key to.
//!
//! The second half binds the box to an approver. `X25519(a, R)` is a
//! static-static agreement between the APPROVER's key and the new device's
//! key: the only two parties who can compute it are the holder of
//! `approver_seed` and the holder of the recipient's seed. So a box that opens
//! under a given approver key was made by that approver (or by the recipient
//! itself, which gains nothing).
//!
//! That is only worth what the approver key is worth, and the approver keys a
//! new device can see come from the server's device list. A server can list a
//! device of its own as an approver, run it, and seal an account key it chose;
//! the box opens, and a store sealed under that key opens too, because the
//! server can serve one of those as well. So which approver to believe is not
//! the server's to say. The new device's door takes a box only when the person
//! vouched for where it came from, one way, the two numbers. The QR code below
//! is described for its format alone: the door refuses every version-2 box.
//!
//! - **The two numbers.** The person picked the approver's number on the new
//!   device ([`crate::device_link::device_link_approver_number`]), which
//!   confirms that approver's key. A version-3 box from THAT key is accepted
//!   ([`account_key_accept_hybrid`]); a version-1 box only under the device's
//!   own test switch, from any listed approver.
//! - **The QR code (removed).** The new device drew a 32-byte link secret
//!   and shows it in its QR code ([`crate::device_link::device_link_qr`]); the
//!   server never sees it. The approver that scanned the code seals a
//!   version-2 box with the secret as a third part of the input keying
//!   material (`account_key_seal_linked`, a test-only sealer now):
//!
//!   ```text
//!   ikm = X25519(e, R) || X25519(a, R) || link_secret
//!   key = HKDF-SHA256(ikm, salt = <empty>, info = "peachy account key v2" || 0x00
//!                     || A_ed || recipient_signing_key || device_id, L = 32)
//!   box = 0x02 || E || nonce(12) || AES-256-GCM(key, nonce, account_key, aad = E)   = 93 bytes
//!   ```
//!
//!   Only a device that read the screen could make one. No client shows or
//!   scans the code, and approvers at or above the minimums seal version 3.
//!
//! ## The hybrid box (version 3)
//!
//! Every input above is X25519, and the recipient key `R` reaches the
//! approver through the server. A party that records the approval today and
//! can break X25519 later would compute `X25519(e, R)` from `E` and `R` and
//! open the account key, and with it everything the account key seals. So a
//! waiting device also draws an X-Wing (ML-KEM-768 + X25519) link key for the
//! pairing, posts it beside its nonce signed by its own key
//! ([`crate::device_link::sign_device_link_kem`]), and the approver, having
//! checked that signature under the key the number was derived over, mixes an
//! X-Wing shared secret into the box key:
//!
//! ```text
//! K    = the waiting device's link key (1216 bytes)
//! info = "peachy account key v3" || 0x00 || A_ed || recipient_signing_key
//!        || SHA-256(K) || device_id
//! (enc, s) = HPKE-Base(X-Wing).SetupS(K, info), s = Export("", 32)
//! ikm  = X25519(e, R) || X25519(a, R) || s
//! key  = HKDF-SHA256(ikm, salt = <empty>, info, L = 32)
//! box  = 0x03 || E || enc(1120) || nonce(12)
//!        || AES-256-GCM(key, nonce, account_key, aad = 0x03 || E || enc)   = 1213 bytes
//! ```
//!
//! Breaking the box now takes breaking both X25519 and ML-KEM-768. The link
//! key is fresh per pairing and its private half never leaves the waiting
//! device, so a box recorded today stays shut after the device has dropped
//! it. [`account_key_seal_hybrid`] seals it; [`account_key_accept_hybrid`]
//! opens it only from the approver key the person confirmed on this device.
//!
//! The one other door is `server_approval_allowed`, a switch only the device
//! itself can set and never from anything the server says: a client sets it
//! for a test server it was built or launched to talk to, and for a sign-in
//! with a number from the range reserved for fiction. Under it a version-1
//! box from any approver the server lists opens; a version-3 box never opens
//! under it (docs/identity.md §Fetching and opening the account
//! key).
//!
//! Both public keys and the new device's row id are in the HKDF `info`, so a
//! box made for one device row cannot be replayed onto another row holding the
//! same key, and a box cannot be re-attributed to a different approver even
//! if some curve coincidence produced the same shared secret. `E` is the AEAD's
//! associated data so the ephemeral half cannot be swapped under a valid
//! ciphertext.
//!
//! Using one Ed25519 key for both signing (device approval) and X25519 (this
//! box) is the standard birational map — the same one libsodium's
//! `crypto_sign_ed25519_sk_to_curve25519` performs — and the two uses are kept
//! apart by construction: a signature is over a domain-separated statement,
//! and this agreement never produces anything that verifies as a signature.
//!
//! ## The transfer-key box
//!
//! A history hand-off to one of the account's own devices is an attachment
//! named by a pointer in a self-note, and a self-note is sealed under the
//! account key alone, which a removed device keeps. So the pointer's
//! attachment key travels in a box of its own sealed to the recipient
//! device's signing key (as its X25519 point) and bound to its row id, under
//! the domain "peachy transfer key v1" ([`transfer_key_seal`],
//! [`transfer_key_open`]). It is that signing key and not the pairing's link
//! key because a sibling answering a later ask for history never saw the
//! pairing; the signing key is the one the sender vouched for either way.
//!
//! ## Refusals
//!
//! Every failure is an ordinary [`Error::InvalidArgument`]. A wrong key, a
//! wrong id, a tampered value, a wrong approver and a wrong device id all
//! surface as "does not open" — the AEAD tag cannot tell them apart and nor
//! should a caller try. Only the SHAPE refusals (a length, a version byte) say
//! what was wrong, because those are a caller's bug and not a fact about a
//! secret.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::credential::ED25519_PUBLIC_KEY_BYTES;
use crate::error::{Error, Result};
use crate::identity::{signing_key_public_key, ED25519_SEED_BYTES};
use crate::secret::Secret;

/// An account key: 32 random bytes, one per account.
pub const ACCOUNT_KEY_BYTES: usize = 32;

/// A record id: exactly 16 bytes, random, minted by a client.
pub const STORE_ID_BYTES: usize = 16;

/// The reserved id the manifest is sealed under. No record may use it.
pub const MANIFEST_ID: [u8; STORE_ID_BYTES] = [0u8; STORE_ID_BYTES];

/// The first byte of every sealed value and every box: the format version.
pub const STORE_FORMAT_VERSION: u8 = 0x01;

/// The largest plaintext [`store_seal`] accepts for a record, before padding.
/// A signed note takes less ([`note_seal_signed`]).
pub const MAX_STORE_PLAINTEXT_BYTES: usize = 65_536;

/// The largest MANIFEST plaintext [`store_seal`] accepts, before padding:
/// room for the server's 10,000 records as 32-hex ids in the JSON manifest
/// (35 bytes each, plus the `{"version":N,"ids":[]}` frame). Sealed, it is
/// well under the server's 512 KiB manifest limit.
///
/// The manifest has its own cap, not the record cap: under the record cap a
/// store would stop at about 1,870 ids, and past that a write adding a subject
/// (a block, a leave) could not seal its manifest at all. [`store_open`] has
/// no size cap in any build, so every reader opens a manifest this large.
pub const MAX_MANIFEST_PLAINTEXT_BYTES: usize = 360_000;

/// Sealed plaintexts are padded to a multiple of this.
pub const STORE_PADDING_BLOCK: usize = 256;

/// The exact length of an account-key box: version, `E`, nonce, key, tag.
pub const ACCOUNT_KEY_BOX_BYTES: usize = 1 + 32 + NONCE_BYTES + ACCOUNT_KEY_BYTES + TAG_BYTES;

/// The HKDF `info` prefix for a record key.
pub const STORE_RECORD_KEY_DOMAIN: &str = "peachy store v1";

/// The HKDF `info` prefix for the account-key box.
pub const ACCOUNT_KEY_BOX_DOMAIN: &str = "peachy account key v1";

/// The HKDF `info` prefix for a box keyed with the QR code's link secret.
pub const ACCOUNT_KEY_BOX_LINKED_DOMAIN: &str = "peachy account key v2";

/// The first byte of a box keyed with the QR code's link secret.
pub const ACCOUNT_KEY_BOX_LINKED_VERSION: u8 = 0x02;

/// The QR code's link secret: 32 bytes.
pub const LINK_KEY_BYTES: usize = 32;

/// The HKDF domain of the hybrid box, whose key also mixes in an X-Wing
/// shared secret with the new device's link key.
pub const ACCOUNT_KEY_BOX_HYBRID_DOMAIN: &str = "peachy account key v3";

/// The first byte of the hybrid box.
pub const ACCOUNT_KEY_BOX_HYBRID_VERSION: u8 = 0x03;

/// An X-Wing encapsulation: ML-KEM-768's 1088-byte ciphertext and X25519's
/// 32-byte ephemeral.
const XWING_ENC_BYTES: usize = 1120;

/// The size of the hybrid box: the version, `E`, the X-Wing encapsulation,
/// the nonce and the sealed account key with its tag. 1,213 bytes.
pub const ACCOUNT_KEY_BOX_HYBRID_BYTES: usize =
    1 + X25519_BYTES + XWING_ENC_BYTES + NONCE_BYTES + ACCOUNT_KEY_BYTES + TAG_BYTES;

const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const X25519_BYTES: usize = 32;

/// The shortest value [`store_open`] will look at: version, nonce, tag and
/// one padding block.
pub const MIN_SEALED_VALUE_BYTES: usize = 1 + NONCE_BYTES + TAG_BYTES + STORE_PADDING_BLOCK;

// ---- The account key --------------------------------------------------------

/// A fresh 32-byte account key from the platform CSPRNG.
///
/// Minted once per account, by the first device that finds no store; every
/// later device receives it in an [`account_key_seal`] box.
pub fn generate_account_key() -> Result<[u8; ACCOUNT_KEY_BYTES]> {
    let mut key = [0u8; ACCOUNT_KEY_BYTES];
    fill_random(&mut key)?;
    Ok(key)
}

fn fill_random(out: &mut [u8]) -> Result<()> {
    getrandom::fill(out)
        .map_err(|err| Error::invalid(format!("no system randomness available: {err}")))
}

// ---- Records ----------------------------------------------------------------

/// `k(id)` — the AES-256 key one record (or the manifest) is sealed under.
///
/// Public so the golden fixture can pin it; a client has no reason to call it,
/// since [`store_seal`] and [`store_open`] derive it themselves.
pub fn record_key(account_key: &[u8], id: &[u8]) -> Result<[u8; 32]> {
    domain_key(STORE_RECORD_KEY_DOMAIN, account_key, id).map(|key| *key)
}

/// `HKDF-SHA256(account_key, info = domain || 0x00 || id)`: the one derivation
/// behind a record's key and a self-note's key, told apart by `domain`.
fn domain_key(domain: &str, account_key: &[u8], id: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let account_key = account_key_arg(account_key)?;
    let id = id_arg(id)?;
    let mut info = Vec::with_capacity(domain.len() + 1 + STORE_ID_BYTES);
    info.extend_from_slice(domain.as_bytes());
    info.push(0);
    info.extend_from_slice(&id);
    hkdf32(&account_key[..], &info)
}

/// Seal `plaintext` as the value stored under `id`.
///
/// `0x01 || nonce || AES-256-GCM(k(id), nonce, pad(plaintext), aad = id)`,
/// with a fresh random nonce. Refuses an account key that is not 32 bytes, an
/// id that is not 16, and a plaintext over [`MAX_STORE_PLAINTEXT_BYTES`] (over
/// [`MAX_MANIFEST_PLAINTEXT_BYTES`] for the manifest, [`MANIFEST_ID`]).
pub fn store_seal(account_key: &[u8], id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_BYTES];
    fill_random(&mut nonce)?;
    seal_record(
        STORE_RECORD_KEY_DOMAIN,
        STORE_FORMAT_VERSION,
        account_key,
        id,
        plaintext,
        &nonce,
        store_plaintext_limit(id),
    )
}

/// The plaintext cap for a value sealed under `id` in the store's domain:
/// the manifest's own, larger one for [`MANIFEST_ID`], the record cap
/// otherwise.
fn store_plaintext_limit(id: &[u8]) -> usize {
    if id == MANIFEST_ID {
        MAX_MANIFEST_PLAINTEXT_BYTES
    } else {
        MAX_STORE_PLAINTEXT_BYTES
    }
}

/// [`store_seal`] with the nonce supplied — for the golden fixture and Rust
/// tests ONLY. A nonce reused under one key and id is the end of AES-GCM, so
/// this is not in any binding and not in a build without the `fixture`
/// feature.
#[cfg(any(test, feature = "fixture"))]
pub fn store_seal_with(
    account_key: &[u8],
    id: &[u8],
    plaintext: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    seal_record(
        STORE_RECORD_KEY_DOMAIN,
        STORE_FORMAT_VERSION,
        account_key,
        id,
        plaintext,
        nonce,
        store_plaintext_limit(id),
    )
}

fn seal_record(
    domain: &str,
    version: u8,
    account_key: &[u8],
    id: &[u8],
    plaintext: &[u8],
    nonce: &[u8; NONCE_BYTES],
    limit: usize,
) -> Result<Vec<u8>> {
    if plaintext.len() > limit {
        return Err(Error::invalid(format!(
            "a store plaintext must be at most {limit} bytes, got {}",
            plaintext.len()
        )));
    }
    let key = domain_key(domain, account_key, id)?;
    let padded = Zeroizing::new(pad(plaintext));
    let cipher = aes(&key)?;
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &padded,
                aad: id,
            },
        )
        .map_err(|_| Error::invalid("the store value could not be sealed"))?;
    let mut value = Vec::with_capacity(1 + NONCE_BYTES + sealed.len());
    value.push(version);
    value.extend_from_slice(nonce);
    value.extend_from_slice(&sealed);
    Ok(value)
}

/// Open a value [`store_seal`] made under the same account key and id.
///
/// Refuses a wrong-length key or id, a value shorter than
/// [`MIN_SEALED_VALUE_BYTES`], an unknown version byte, a value that does not
/// open ("does not open": wrong key, wrong id, or tampered — deliberately one
/// answer), and a plaintext whose padding is not `0x80` then zeros.
pub fn store_open(account_key: &[u8], id: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    open_record(
        STORE_RECORD_KEY_DOMAIN,
        STORE_FORMAT_VERSION,
        account_key,
        id,
        value,
    )
}

fn open_record(
    domain: &str,
    expected_version: u8,
    account_key: &[u8],
    id: &[u8],
    value: &[u8],
) -> Result<Vec<u8>> {
    let key = domain_key(domain, account_key, id)?;
    if value.len() < MIN_SEALED_VALUE_BYTES {
        return Err(Error::invalid(format!(
            "a sealed store value is too short: {} bytes, at least {MIN_SEALED_VALUE_BYTES}",
            value.len()
        )));
    }
    let (version, rest) = value
        .split_first()
        .ok_or_else(|| Error::invalid("a sealed store value is empty"))?;
    if *version != expected_version {
        return Err(Error::invalid(format!(
            "unknown store format version 0x{version:02x}; this build reads 0x{expected_version:02x}"
        )));
    }
    let (nonce, sealed) = rest
        .split_at_checked(NONCE_BYTES)
        .ok_or_else(|| Error::invalid("a sealed store value is too short to carry its nonce"))?;
    // Wiped if the padding is refused; handed to the caller whole if not.
    let mut padded = Secret::new(
        aes(&key)?
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: id,
                },
            )
            .map_err(|_| Error::invalid("the store value does not open under this key and id"))?,
    );
    unpad(&mut padded)?;
    Ok(std::mem::take(&mut *padded))
}

// ---- Self-notes -------------------------------------------------------------
//
// A note from one of an account's devices to its others, carried by the
// server's mailbox (docs/delivery.md §Self-notes):
// "I read this conversation up to here", "here is your history". Sealed exactly
// as a store record is, under a key from a DIFFERENT domain, so a note can never
// be replayed into the store as a record, or a record into the mailbox as a
// note, even under the same 16-byte id.
//
// ```text
// k(id) = HKDF-SHA256(ikm = account_key, salt = <empty>,
//                     info = "peachy self note v1" || 0x00 || id, L = 32)
// note  = 0x01 || nonce(12) || AES-256-GCM(k(id), nonce, pad(plaintext), aad = id)
// ```
//
// On the wire a client sent `id(16) || note`, with a fresh random id per note.
//
// THIS IS THE OLDER, UNSIGNED FORMAT. No build sends or opens it any more: a
// note is the signed one below (`note_seal_signed`,
// docs/sealed-messages.md §Signed notes). Only the tests seal one, to
// show it is refused.

/// The HKDF info prefix of a self-note's key.
pub const NOTE_KEY_DOMAIN: &str = "peachy self note v1";

/// `k(id)` for an unsigned self-note: tests only.
#[cfg(any(test, feature = "fixture"))]
pub fn note_key(account_key: &[u8], id: &[u8]) -> Result<[u8; 32]> {
    domain_key(NOTE_KEY_DOMAIN, account_key, id).map(|key| *key)
}

/// An unsigned self-note, as builds before the signed note sealed one, with
/// the nonce supplied: tests only, to show it is refused.
#[cfg(any(test, feature = "fixture"))]
pub fn note_seal_with(
    account_key: &[u8],
    id: &[u8],
    plaintext: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    seal_record(
        NOTE_KEY_DOMAIN,
        STORE_FORMAT_VERSION,
        account_key,
        id,
        plaintext,
        nonce,
        MAX_STORE_PLAINTEXT_BYTES,
    )
}

// ---- Signed self-notes ------------------------------------------------------
//
// A version-1 note proves only that its maker holds the account key, and it
// says nothing about WHEN, so the server, which keeps what it delivers until
// it is acked, could hand a note it once carried to a device again. A history
// hand-off is a list of messages with an author on each, so a note anybody
// with the key could make, or a genuine one delivered twice, would put words
// in other people's mouths in the person's own transcripts.
//
// So a note now says which of the account's devices sent it and when, and
// that device signs it with its own Ed25519 key, the one its MLS leaf carries:
//
// ```text
// k2(id) = HKDF-SHA256(ikm = account_key, salt = <empty>,
//                      info = "peachy self note v2" || 0x00 || id, L = 32)
// body   = u8(len(sender)) || sender || BE64(issued_at_ms) || plaintext
// sig    = Ed25519(sender's device seed,
//                  "peachy-self-note-v2" || 0x00 || id || body)
// note   = 0x02 || nonce(12) || AES-256-GCM(k2(id), nonce, pad(body || sig), aad = id)
// ```
//
// `sender` is the sending device's `devices.id`. The signature is INSIDE the
// seal: the server already knows which login sent a note, and it gains no
// signed statement to hold. The receiver opens the note, reads who claims to
// have sent it ([`note_sender`]), looks that device up in its own account's
// device list (live, approved and certified by the account key), and opens it
// for real only against that device's signing key ([`note_open_signed`]),
// which also refuses a note issued more than [`NOTE_MAX_AGE_MS`] ago or more
// than [`NOTE_MAX_AHEAD_MS`] ahead of the receiver's clock. Within that window
// a receiver drops a note id it has already acted on, so a note acts once.
//
// What this does not do: any row the device list shows as live, approved and
// certified can sign. The server alone cannot send a note that acts:
// receivers refuse version-1 notes (`docs/sealed-messages.md`
// §Signed notes), so the account key alone makes nothing a receiver acts on.

/// The HKDF info prefix of a signed note's key. A different domain from
/// [`NOTE_KEY_DOMAIN`], so a version-1 note and a signed one never open as
/// each other.
pub const NOTE_SIGNED_KEY_DOMAIN: &str = "peachy self note v2";

/// What the sending device signs: this, `0x00`, the note id, and the body.
pub const NOTE_SIGNATURE_DOMAIN: &str = "peachy-self-note-v2";

/// The first byte of a signed note.
pub const NOTE_SIGNED_VERSION: u8 = 0x02;

/// The oldest a signed note may be when it is opened: seven days.
pub const NOTE_MAX_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// How far ahead of the receiver's clock a signed note may be dated: ten
/// minutes, for two phones whose clocks disagree.
pub const NOTE_MAX_AHEAD_MS: i64 = 10 * 60 * 1000;

/// The longest sender device id a signed note carries.
pub const MAX_NOTE_SENDER_BYTES: usize = 255;

const NOTE_SIGNATURE_BYTES: usize = 64;

/// The bytes a signed note's plaintext is wrapped in, beyond the sender id.
const NOTE_SIGNED_OVERHEAD: usize = 1 + 8 + NOTE_SIGNATURE_BYTES;

/// `k2(id)` for a signed note. Public for the golden fixture only.
pub fn note_signed_key(account_key: &[u8], id: &[u8]) -> Result<[u8; 32]> {
    domain_key(NOTE_SIGNED_KEY_DOMAIN, account_key, id).map(|key| *key)
}

/// Seal a self-note under the account key and sign it as this device.
///
/// `sender_device_id` is this device's own `devices.id`, `issued_at_ms` the
/// device's clock in unix milliseconds, and `device_seed` the 32-byte Ed25519
/// seed of the key that row carries. The other arguments and limits are
/// a record's ([`MAX_STORE_PLAINTEXT_BYTES`]), less the bytes the sender, the
/// time and the signature take.
pub fn note_seal_signed(
    account_key: &[u8],
    id: &[u8],
    plaintext: &[u8],
    sender_device_id: &str,
    issued_at_ms: i64,
    device_seed: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_BYTES];
    fill_random(&mut nonce)?;
    seal_signed(
        account_key,
        id,
        plaintext,
        sender_device_id,
        issued_at_ms,
        device_seed,
        &nonce,
    )
}

/// [`note_seal_signed`] with the nonce supplied: fixture and tests only.
#[cfg(any(test, feature = "fixture"))]
pub fn note_seal_signed_with(
    account_key: &[u8],
    id: &[u8],
    plaintext: &[u8],
    sender_device_id: &str,
    issued_at_ms: i64,
    device_seed: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    seal_signed(
        account_key,
        id,
        plaintext,
        sender_device_id,
        issued_at_ms,
        device_seed,
        nonce,
    )
}

fn seal_signed(
    account_key: &[u8],
    id: &[u8],
    plaintext: &[u8],
    sender_device_id: &str,
    issued_at_ms: i64,
    device_seed: &[u8],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Vec<u8>> {
    let seed = seed_arg(device_seed, "device_seed")?;
    let id_bytes = id_arg(id)?;
    let sender = sender_arg(sender_device_id)?;
    if issued_at_ms < 0 {
        return Err(Error::invalid(
            "a signed note's issued_at_ms must not be negative",
        ));
    }
    let limit = MAX_STORE_PLAINTEXT_BYTES - NOTE_SIGNED_OVERHEAD - sender.len();
    if plaintext.len() > limit {
        return Err(Error::invalid(format!(
            "a signed note's plaintext must be at most {limit} bytes, got {}",
            plaintext.len()
        )));
    }
    let mut inner = Zeroizing::new(Vec::with_capacity(
        NOTE_SIGNED_OVERHEAD + sender.len() + plaintext.len(),
    ));
    #[allow(clippy::cast_possible_truncation)] // sender_arg caps it at 255
    inner.push(sender.len() as u8);
    inner.extend_from_slice(sender);
    inner.extend_from_slice(&issued_at_ms.to_be_bytes());
    inner.extend_from_slice(plaintext);
    let signature = SigningKey::from_bytes(&seed)
        .sign(&note_statement(&id_bytes, &inner))
        .to_bytes();
    inner.extend_from_slice(&signature);
    seal_record(
        NOTE_SIGNED_KEY_DOMAIN,
        NOTE_SIGNED_VERSION,
        account_key,
        id,
        &inner,
        nonce,
        MAX_STORE_PLAINTEXT_BYTES,
    )
}

/// `"peachy-self-note-v2" || 0x00 || id || body`.
fn note_statement(id: &[u8; STORE_ID_BYTES], body: &[u8]) -> Vec<u8> {
    let mut statement =
        Vec::with_capacity(NOTE_SIGNATURE_DOMAIN.len() + 1 + STORE_ID_BYTES + body.len());
    statement.extend_from_slice(NOTE_SIGNATURE_DOMAIN.as_bytes());
    statement.push(0);
    statement.extend_from_slice(id);
    statement.extend_from_slice(body);
    statement
}

/// A signed note, opened and taken apart but not yet believed.
struct UnverifiedNote {
    sender: String,
    issued_at_ms: i64,
    /// `u8(len) || sender || BE64(issued_at) || plaintext`: what was signed
    /// after the domain and the id. Wiped when this drops.
    body: zeroize::Zeroizing<Vec<u8>>,
    plaintext_at: usize,
    signature: [u8; NOTE_SIGNATURE_BYTES],
}

fn open_unverified(account_key: &[u8], id: &[u8], value: &[u8]) -> Result<UnverifiedNote> {
    if value.first() == Some(&STORE_FORMAT_VERSION) {
        return Err(Error::invalid(
            "an unsigned (version 1) self-note: it names no device that sent it",
        ));
    }
    // Wiped on every refusal below; the body is carried on, wiped, in the
    // note.
    let mut inner = Secret::new(open_record(
        NOTE_SIGNED_KEY_DOMAIN,
        NOTE_SIGNED_VERSION,
        account_key,
        id,
        value,
    )?);
    let malformed = || Error::invalid("a signed self-note is malformed inside its seal");
    if inner.len() < NOTE_SIGNED_OVERHEAD {
        return Err(malformed());
    }
    let signature_at = inner.len() - NOTE_SIGNATURE_BYTES;
    let signature: [u8; NOTE_SIGNATURE_BYTES] = inner
        .split_off(signature_at)
        .try_into()
        .map_err(|_| malformed())?;
    let body = Zeroizing::new(std::mem::take(&mut *inner));
    let sender_len = usize::from(*body.first().ok_or_else(malformed)?);
    let plaintext_at = 1 + sender_len + 8;
    if sender_len == 0 || body.len() < plaintext_at {
        return Err(malformed());
    }
    let sender = std::str::from_utf8(&body[1..1 + sender_len])
        .map_err(|_| malformed())?
        .to_owned();
    let issued: [u8; 8] = body[1 + sender_len..plaintext_at]
        .try_into()
        .map_err(|_| malformed())?;
    Ok(UnverifiedNote {
        sender,
        issued_at_ms: i64::from_be_bytes(issued),
        body,
        plaintext_at,
        signature,
    })
}

/// The device a signed note SAYS sent it: what the receiver looks up in its
/// own account's device list before it calls [`note_open_signed`]. Nothing
/// here is believed yet; the claim is checked there.
///
/// Refuses a version-1 note (no sender), a value that does not open under
/// this account key and id, and a malformed one.
pub fn note_sender(account_key: &[u8], id: &[u8], value: &[u8]) -> Result<String> {
    Ok(open_unverified(account_key, id, value)?.sender)
}

/// Open a signed note, believing it only when `sender_device_id` sent it.
///
/// `sender_signing_key` is the 32-byte Ed25519 public key the receiver's own
/// device list gives `sender_device_id`, a device that list shows as live,
/// approved and certified by the account key. `now_ms` is the receiver's
/// clock. Returns the plaintext [`note_seal_signed`] was given.
///
/// Refuses, besides everything [`note_sender`] refuses: a note that names
/// another sender, a signature that does not verify under that key (strictly:
/// no small-order or non-canonical key), a note issued more than
/// [`NOTE_MAX_AGE_MS`] before `now_ms`, and one dated more than
/// [`NOTE_MAX_AHEAD_MS`] after it.
pub fn note_open_signed(
    account_key: &[u8],
    id: &[u8],
    value: &[u8],
    sender_device_id: &str,
    sender_signing_key: &[u8],
    now_ms: i64,
) -> Result<Vec<u8>> {
    let key = public_key_arg(sender_signing_key, "sender_signing_key")?;
    let id_bytes = id_arg(id)?;
    let mut note = open_unverified(account_key, id, value)?;
    if note.sender != sender_device_id {
        return Err(Error::invalid(format!(
            "the self-note names device {:?} as its sender, not {sender_device_id:?}",
            note.sender
        )));
    }
    let verifying = VerifyingKey::from_bytes(&key)
        .map_err(|_| Error::invalid("the sender_signing_key is not a valid Ed25519 key"))?;
    verifying
        .verify_strict(
            &note_statement(&id_bytes, &note.body),
            &Signature::from_bytes(&note.signature),
        )
        .map_err(|_| Error::invalid("the self-note's signature does not verify for its sender"))?;
    if now_ms.saturating_sub(note.issued_at_ms) > NOTE_MAX_AGE_MS {
        return Err(Error::invalid(
            "the self-note is stale: issued more than seven days ago",
        ));
    }
    if note.issued_at_ms.saturating_sub(now_ms) > NOTE_MAX_AHEAD_MS {
        return Err(Error::invalid(
            "the self-note is dated ahead of this device's clock",
        ));
    }
    Ok(note.body.split_off(note.plaintext_at))
}

fn sender_arg(sender: &str) -> Result<&[u8]> {
    if sender.is_empty() {
        return Err(Error::invalid("a sender_device_id must not be empty"));
    }
    if sender.len() > MAX_NOTE_SENDER_BYTES {
        return Err(Error::invalid(format!(
            "a sender_device_id must be at most {MAX_NOTE_SENDER_BYTES} bytes, got {}",
            sender.len()
        )));
    }
    Ok(sender.as_bytes())
}

/// `p || 0x80 || 0x00 * n`, `n` the least that makes the length a multiple of
/// [`STORE_PADDING_BLOCK`]. Always at least one byte longer than `p`.
fn pad(plaintext: &[u8]) -> Vec<u8> {
    let unpadded = plaintext.len() + 1;
    let padded = unpadded.div_ceil(STORE_PADDING_BLOCK) * STORE_PADDING_BLOCK;
    let mut out = Vec::with_capacity(padded);
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(padded, 0);
    out
}

/// Strip trailing zeros, then exactly one `0x80`, in place. Anything else is
/// refused: a value that opened under the right key and still is not padded
/// was made by something that is not this module.
fn unpad(padded: &mut Vec<u8>) -> Result<()> {
    while padded.last() == Some(&0) {
        padded.pop();
    }
    if padded.pop() != Some(0x80) {
        return Err(Error::invalid(
            "the opened store value is not padded: no 0x80 before the trailing zeros",
        ));
    }
    Ok(())
}

// ---- The account-key box ----------------------------------------------------

/// Seal `account_key` for a newly approved device.
///
/// `approver_seed` is THIS device's 32-byte Ed25519 seed (the one it signs
/// approvals with); `recipient_signing_key` is the new device's 32-byte
/// Ed25519 public key — the one the person scanned or matched; `device_id` is
/// the new device's `devices.id`. Returns the 93-byte box. Read the module
/// header for why the approver's own key goes into the agreement.
pub fn account_key_seal(
    approver_seed: &[u8],
    recipient_signing_key: &[u8],
    device_id: &str,
    account_key: &[u8],
) -> Result<Vec<u8>> {
    // The ephemeral private key, wiped when dropped: with the recipient's
    // public key it gives one of the box's shared secrets.
    let mut ephemeral = Zeroizing::new([0u8; X25519_BYTES]);
    fill_random(&mut ephemeral[..])?;
    let mut nonce = [0u8; NONCE_BYTES];
    fill_random(&mut nonce)?;
    seal_box(
        approver_seed,
        recipient_signing_key,
        device_id,
        account_key,
        None,
        &ephemeral,
        &nonce,
    )
}

/// Seal `account_key` for a new device whose QR code this device scanned: the
/// version-2 box, keyed with the `link_secret` the code carried
/// ([`crate::device_link::device_link_qr_secret`]). The arguments are
/// [`account_key_seal`]'s and the 32-byte secret. Returns 93 bytes.
///
/// For the golden fixture and Rust tests ONLY: no client seals this box any
/// more, no binding exports it, and the new device's door refuses it.
#[cfg(any(test, feature = "fixture"))]
pub fn account_key_seal_linked(
    approver_seed: &[u8],
    recipient_signing_key: &[u8],
    device_id: &str,
    account_key: &[u8],
    link_secret: &[u8],
) -> Result<Vec<u8>> {
    let secret = link_secret_arg(link_secret)?;
    // The ephemeral private key, wiped when dropped: with the recipient's
    // public key it gives one of the box's shared secrets.
    let mut ephemeral = Zeroizing::new([0u8; X25519_BYTES]);
    fill_random(&mut ephemeral[..])?;
    let mut nonce = [0u8; NONCE_BYTES];
    fill_random(&mut nonce)?;
    seal_box(
        approver_seed,
        recipient_signing_key,
        device_id,
        account_key,
        Some(&secret),
        &ephemeral,
        &nonce,
    )
}

/// [`account_key_seal`] with the ephemeral secret and the nonce supplied —
/// for the golden fixture and Rust tests ONLY, like [`store_seal_with`].
#[cfg(any(test, feature = "fixture"))]
pub fn account_key_seal_with(
    approver_seed: &[u8],
    recipient_signing_key: &[u8],
    device_id: &str,
    account_key: &[u8],
    ephemeral: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    seal_box(
        approver_seed,
        recipient_signing_key,
        device_id,
        account_key,
        None,
        ephemeral,
        nonce,
    )
}

/// [`account_key_seal_linked`] with the ephemeral secret and the nonce
/// supplied — for the golden fixture and Rust tests ONLY.
#[cfg(any(test, feature = "fixture"))]
pub fn account_key_seal_linked_with(
    approver_seed: &[u8],
    recipient_signing_key: &[u8],
    device_id: &str,
    account_key: &[u8],
    link_secret: &[u8],
    ephemeral: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    let secret = link_secret_arg(link_secret)?;
    seal_box(
        approver_seed,
        recipient_signing_key,
        device_id,
        account_key,
        Some(&secret),
        ephemeral,
        nonce,
    )
}

fn seal_box(
    approver_seed: &[u8],
    recipient_signing_key: &[u8],
    device_id: &str,
    account_key: &[u8],
    link_secret: Option<&[u8; LINK_KEY_BYTES]>,
    ephemeral: &[u8; X25519_BYTES],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Vec<u8>> {
    let approver_seed = seed_arg(approver_seed, "approver_seed")?;
    let recipient_signing_key = public_key_arg(recipient_signing_key, "recipient_signing_key")?;
    let account_key = account_key_arg(account_key)?;
    device_id_arg(device_id)?;

    let approver_signing_key = signing_key_public_key(&approver_seed[..])?;
    let recipient = montgomery(&recipient_signing_key, "recipient_signing_key")?;
    let approver_secret = x25519_secret(&approver_seed);

    let ephemeral_public = MontgomeryPoint::mul_base_clamped(*ephemeral).to_bytes();
    let mut ikm = Zeroizing::new(Vec::with_capacity(2 * X25519_BYTES + LINK_KEY_BYTES));
    ikm.extend_from_slice(&*shared(recipient, ephemeral)?);
    ikm.extend_from_slice(&*shared(recipient, &approver_secret)?);
    if let Some(secret) = link_secret {
        ikm.extend_from_slice(secret);
    }
    let key = box_key(
        &ikm,
        link_secret.is_some(),
        &approver_signing_key,
        &recipient_signing_key,
        device_id,
    )?;

    let sealed = aes(&key)?
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &account_key[..],
                aad: &ephemeral_public,
            },
        )
        .map_err(|_| Error::invalid("the account key box could not be sealed"))?;
    let mut sealed_box = Vec::with_capacity(ACCOUNT_KEY_BOX_BYTES);
    sealed_box.push(if link_secret.is_some() {
        ACCOUNT_KEY_BOX_LINKED_VERSION
    } else {
        STORE_FORMAT_VERSION
    });
    sealed_box.extend_from_slice(&ephemeral_public);
    sealed_box.extend_from_slice(nonce);
    sealed_box.extend_from_slice(&sealed);
    Ok(sealed_box)
}

/// Open an account-key box on the device it was made for.
///
/// `recipient_seed` is THIS device's 32-byte Ed25519 seed;
/// `approver_signing_key` is the approving device's public key — which the
/// caller must take from a device on its own approver list,
/// never from the same response that carried the box; `device_id` is this
/// device's own `devices.id`. Returns the 32-byte account key.
///
/// A box made by a different approver, for a different device row, or altered
/// in transit, "does not open" — one answer for all three.
///
/// This opens a version-1 box and nothing else, and says nothing about whether
/// the approver is one the person vouched for: whoever lists the approver,
/// the server included, picks the key it opens to. A client takes a key only
/// through [`account_key_accept_hybrid`], under the person's confirmation of
/// the approver's number; this is the primitive under it, public only with
/// the `fixture` feature, for tests and tools.
#[cfg(any(test, feature = "fixture"))]
pub fn account_key_open(
    recipient_seed: &[u8],
    approver_signing_key: &[u8],
    device_id: &str,
    sealed_box: &[u8],
) -> Result<[u8; ACCOUNT_KEY_BYTES]> {
    open_box(
        recipient_seed,
        approver_signing_key,
        device_id,
        sealed_box,
        None,
    )
}

/// THE NEW DEVICE'S DOOR for an account key: open the box only when the person
/// vouched for the device that sealed it (module header, "The account-key
/// box").
///
/// - `link_secret`: the 32 bytes this device's QR code showed, or empty when
///   it showed none. A version-2 box opens only with it.
/// - `confirmed_approver_key`: the approver key whose number the person picked
///   on this device, or empty. A version-1 box opens only when
///   `approver_signing_key` is exactly that key.
/// - `server_approval_allowed`: this device's own switch (never set from
///   anything the server says) that lets a version-1 box from any listed
///   approver open, for test servers and sign-ins with a fictional number.
///
/// The other arguments are [`account_key_open`]'s. A refusal is
/// [`Error::InvalidArgument`] whose message says which rule refused it.
///
/// Not a door of its own: [`account_key_accept_hybrid`], the one a client
/// calls, takes the boxes this takes under its stricter rule, and the
/// fixture harness replays this one's table.
pub(crate) fn account_key_accept(
    recipient_seed: &[u8],
    approver_signing_key: &[u8],
    device_id: &str,
    sealed_box: &[u8],
    link_secret: &[u8],
    confirmed_approver_key: &[u8],
    server_approval_allowed: bool,
) -> Result<[u8; ACCOUNT_KEY_BYTES]> {
    match sealed_box.first() {
        Some(&ACCOUNT_KEY_BOX_LINKED_VERSION) => {
            if link_secret.is_empty() {
                return Err(Error::invalid(
                    "a box keyed with a QR code's link secret, and this device showed no QR code",
                ));
            }
            let secret = link_secret_arg(link_secret)?;
            open_box(
                recipient_seed,
                approver_signing_key,
                device_id,
                sealed_box,
                Some(&secret),
            )
        }
        _ => {
            let confirmed = !confirmed_approver_key.is_empty()
                && confirmed_approver_key.len() == ED25519_PUBLIC_KEY_BYTES
                && confirmed_approver_key == approver_signing_key;
            if !confirmed && !server_approval_allowed {
                return Err(Error::invalid(
                    "an account key box from an approver the person did not confirm on this device",
                ));
            }
            open_box(
                recipient_seed,
                approver_signing_key,
                device_id,
                sealed_box,
                None,
            )
        }
    }
}

fn open_box(
    recipient_seed: &[u8],
    approver_signing_key: &[u8],
    device_id: &str,
    sealed_box: &[u8],
    link_secret: Option<&[u8; LINK_KEY_BYTES]>,
) -> Result<[u8; ACCOUNT_KEY_BYTES]> {
    let recipient_seed = seed_arg(recipient_seed, "recipient_seed")?;
    let approver_signing_key = public_key_arg(approver_signing_key, "approver_signing_key")?;
    device_id_arg(device_id)?;
    if sealed_box.len() != ACCOUNT_KEY_BOX_BYTES {
        return Err(Error::invalid(format!(
            "an account key box must be exactly {ACCOUNT_KEY_BOX_BYTES} bytes, got {}",
            sealed_box.len()
        )));
    }
    let (version, rest) = sealed_box
        .split_first()
        .ok_or_else(|| Error::invalid("an account key box is empty"))?;
    let expected = if link_secret.is_some() {
        ACCOUNT_KEY_BOX_LINKED_VERSION
    } else {
        STORE_FORMAT_VERSION
    };
    if *version != expected {
        return Err(
            if *version == STORE_FORMAT_VERSION || *version == ACCOUNT_KEY_BOX_LINKED_VERSION {
                Error::invalid(format!(
                    "account key box format version 0x{version:02x}; this call reads 0x{expected:02x}"
                ))
            } else {
                Error::invalid(format!(
                    "unknown account key box format version 0x{version:02x}; this build reads \
                     0x{STORE_FORMAT_VERSION:02x} and 0x{ACCOUNT_KEY_BOX_LINKED_VERSION:02x}"
                ))
            },
        );
    }
    let (ephemeral_public, rest) = rest
        .split_at_checked(X25519_BYTES)
        .ok_or_else(|| Error::invalid("an account key box is too short"))?;
    let (nonce, sealed) = rest
        .split_at_checked(NONCE_BYTES)
        .ok_or_else(|| Error::invalid("an account key box is too short"))?;
    let ephemeral_public: [u8; X25519_BYTES] = ephemeral_public
        .try_into()
        .map_err(|_| Error::invalid("an account key box is too short"))?;

    let recipient_signing_key = signing_key_public_key(&recipient_seed[..])?;
    let approver = montgomery(&approver_signing_key, "approver_signing_key")?;
    let recipient_secret = x25519_secret(&recipient_seed);

    let mut ikm = Zeroizing::new(Vec::with_capacity(2 * X25519_BYTES + LINK_KEY_BYTES));
    ikm.extend_from_slice(&*shared(
        MontgomeryPoint(ephemeral_public),
        &recipient_secret,
    )?);
    ikm.extend_from_slice(&*shared(approver, &recipient_secret)?);
    if let Some(secret) = link_secret {
        ikm.extend_from_slice(secret);
    }
    let key = box_key(
        &ikm,
        link_secret.is_some(),
        &approver_signing_key,
        &recipient_signing_key,
        device_id,
    )?;

    let opened = Zeroizing::new(
        aes(&key)?
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: &ephemeral_public,
                },
            )
            .map_err(|_| {
                Error::invalid(
                    "the account key box does not open for this device, approver and device id",
                )
            })?,
    );
    <[u8; ACCOUNT_KEY_BYTES]>::try_from(opened.as_slice()).map_err(|_| {
        Error::invalid(format!(
            "an account key box opened to {} bytes, not {ACCOUNT_KEY_BYTES}",
            opened.len()
        ))
    })
}

// ---- The hybrid (post-quantum) account-key box -------------------------------

/// Seal `account_key` for a newly approved device that posted a link key: the
/// version-3 box (module header, "The hybrid box"). `recipient_link_key` is
/// the 1216-byte X-Wing key the waiting device posted with its nonce, which
/// the caller MUST have checked with
/// [`crate::device_link::verify_device_link_kem`] under the key the number was
/// derived over. The other arguments are [`account_key_seal`]'s. Returns
/// [`ACCOUNT_KEY_BOX_HYBRID_BYTES`] bytes.
pub fn account_key_seal_hybrid(
    approver_seed: &[u8],
    recipient_signing_key: &[u8],
    recipient_link_key: &[u8],
    device_id: &str,
    account_key: &[u8],
) -> Result<Vec<u8>> {
    let approver_seed = seed_arg(approver_seed, "approver_seed")?;
    let recipient_signing_key = public_key_arg(recipient_signing_key, "recipient_signing_key")?;
    let account_key = account_key_arg(account_key)?;
    device_id_arg(device_id)?;
    link_key_arg(recipient_link_key)?;

    let approver_signing_key = signing_key_public_key(&approver_seed[..])?;
    let recipient = montgomery(&recipient_signing_key, "recipient_signing_key")?;
    let approver_secret = x25519_secret(&approver_seed);

    // The ephemeral private key, wiped when dropped: with the recipient's
    // public key it gives one of the box's shared secrets.
    let mut ephemeral = Zeroizing::new([0u8; X25519_BYTES]);
    fill_random(&mut ephemeral[..])?;
    let mut nonce = [0u8; NONCE_BYTES];
    fill_random(&mut nonce)?;
    let ephemeral_public = MontgomeryPoint::mul_base_clamped(*ephemeral).to_bytes();

    let info = hybrid_info(
        &approver_signing_key,
        &recipient_signing_key,
        recipient_link_key,
        device_id,
    );
    let (enc, kem_secret) = RustCrypto::default()
        .hpke_setup_sender_and_export(
            crate::device_link::DEVICE_LINK_KEM_HPKE,
            recipient_link_key,
            &info,
            &[],
            32,
        )
        .map_err(|_| Error::invalid("the link key does not take an encapsulation"))?;
    if enc.len() != XWING_ENC_BYTES {
        return Err(Error::invalid(format!(
            "an X-Wing encapsulation is {XWING_ENC_BYTES} bytes, the KEM made {}",
            enc.len()
        )));
    }

    let mut ikm = Zeroizing::new(Vec::with_capacity(3 * 32));
    ikm.extend_from_slice(&*shared(recipient, &ephemeral)?);
    ikm.extend_from_slice(&*shared(recipient, &approver_secret)?);
    ikm.extend_from_slice(&kem_secret);
    let key = hkdf32(&ikm, &info)?;

    let mut aad = Vec::with_capacity(1 + X25519_BYTES + XWING_ENC_BYTES);
    aad.push(ACCOUNT_KEY_BOX_HYBRID_VERSION);
    aad.extend_from_slice(&ephemeral_public);
    aad.extend_from_slice(&enc);
    let sealed = aes(&key)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &account_key[..],
                aad: &aad,
            },
        )
        .map_err(|_| Error::invalid("the account key box could not be sealed"))?;

    let mut sealed_box = aad;
    sealed_box.extend_from_slice(&nonce);
    sealed_box.extend_from_slice(&sealed);
    debug_assert_eq!(sealed_box.len(), ACCOUNT_KEY_BOX_HYBRID_BYTES);
    Ok(sealed_box)
}

/// THE NEW DEVICE'S DOOR for an account key, from builds that post a link
/// key: the version-3 box, and the older boxes under the rules below.
///
/// - `link_key_seed`: the 32-byte seed of the link key this device posted in
///   the pairing ([`crate::device_link::device_link_kem_public_key`]), or
///   empty when it posted none. A version-3 box opens only with it.
/// - A version-1 (X25519-only) box from a confirmed approver is refused;
///   only `server_approval_allowed` still lets one open, for the approvals a
///   test server makes itself.
///
/// A version-3 box opens only from the approver key the person confirmed by
/// its number on this device; `server_approval_allowed` never opens one. A
/// version-2 box (the removed QR code's) never opens here.
///
/// - `confirmed_approver_key`: the approver key whose number the person
///   picked on this device, or empty.
/// - `server_approval_allowed`: this device's own switch (never set from
///   anything the server says), for test servers and sign-ins with a
///   fictional number.
///
/// The other arguments are [`account_key_open`]'s. A refusal is
/// [`Error::InvalidArgument`] whose message says which rule refused it.
#[allow(clippy::too_many_arguments)]
pub fn account_key_accept_hybrid(
    recipient_seed: &[u8],
    approver_signing_key: &[u8],
    device_id: &str,
    sealed_box: &[u8],
    link_key_seed: &[u8],
    confirmed_approver_key: &[u8],
    server_approval_allowed: bool,
) -> Result<[u8; ACCOUNT_KEY_BYTES]> {
    let confirmed = !confirmed_approver_key.is_empty()
        && confirmed_approver_key.len() == ED25519_PUBLIC_KEY_BYTES
        && confirmed_approver_key == approver_signing_key;
    match sealed_box.first() {
        Some(&ACCOUNT_KEY_BOX_HYBRID_VERSION) => {
            // The switch never stands in for the person's pick here: it
            // opens only a version-1 box.
            if !confirmed {
                return Err(Error::invalid(
                    "an account key box from an approver the person did not confirm on this device",
                ));
            }
            if link_key_seed.is_empty() {
                return Err(Error::invalid(
                    "a box sealed to a link key, and this device posted none",
                ));
            }
            open_hybrid_box(
                recipient_seed,
                approver_signing_key,
                device_id,
                sealed_box,
                link_key_seed,
            )
        }
        Some(&ACCOUNT_KEY_BOX_LINKED_VERSION) => account_key_accept(
            recipient_seed,
            approver_signing_key,
            device_id,
            sealed_box,
            &[],
            confirmed_approver_key,
            server_approval_allowed,
        ),
        _ => {
            if !server_approval_allowed {
                return Err(Error::invalid(
                    "an X25519-only account key box, and this build takes only the post-quantum box",
                ));
            }
            account_key_accept(
                recipient_seed,
                approver_signing_key,
                device_id,
                sealed_box,
                &[],
                confirmed_approver_key,
                server_approval_allowed,
            )
        }
    }
}

fn open_hybrid_box(
    recipient_seed: &[u8],
    approver_signing_key: &[u8],
    device_id: &str,
    sealed_box: &[u8],
    link_key_seed: &[u8],
) -> Result<[u8; ACCOUNT_KEY_BYTES]> {
    let recipient_seed = seed_arg(recipient_seed, "recipient_seed")?;
    let approver_signing_key = public_key_arg(approver_signing_key, "approver_signing_key")?;
    device_id_arg(device_id)?;
    if sealed_box.len() != ACCOUNT_KEY_BOX_HYBRID_BYTES {
        return Err(Error::invalid(format!(
            "a version-3 account key box must be exactly {ACCOUNT_KEY_BOX_HYBRID_BYTES} bytes, got {}",
            sealed_box.len()
        )));
    }
    let link_key = crate::device_link::device_link_kem_public_key(link_key_seed)?;
    let link_private = crate::device_link::device_link_kem_private_key(link_key_seed)?;

    let (aad, rest) = sealed_box.split_at(1 + X25519_BYTES + XWING_ENC_BYTES);
    let (nonce, sealed) = rest.split_at(NONCE_BYTES);
    let ephemeral_public: [u8; X25519_BYTES] = aad[1..1 + X25519_BYTES]
        .try_into()
        .map_err(|_| Error::invalid("an account key box is too short"))?;
    let enc = &aad[1 + X25519_BYTES..];

    let recipient_signing_key = signing_key_public_key(&recipient_seed[..])?;
    let approver = montgomery(&approver_signing_key, "approver_signing_key")?;
    let recipient_secret = x25519_secret(&recipient_seed);

    let info = hybrid_info(
        &approver_signing_key,
        &recipient_signing_key,
        &link_key,
        device_id,
    );
    let does_not_open = || {
        Error::invalid(
            "the account key box does not open for this device, approver, link key and device id",
        )
    };
    let kem_secret = RustCrypto::default()
        .hpke_setup_receiver_and_export(
            crate::device_link::DEVICE_LINK_KEM_HPKE,
            enc,
            &link_private,
            &info,
            &[],
            32,
        )
        .map_err(|_| does_not_open())?;

    let mut ikm = Zeroizing::new(Vec::with_capacity(3 * 32));
    ikm.extend_from_slice(&*shared(
        MontgomeryPoint(ephemeral_public),
        &recipient_secret,
    )?);
    ikm.extend_from_slice(&*shared(approver, &recipient_secret)?);
    ikm.extend_from_slice(&kem_secret);
    let key = hkdf32(&ikm, &info)?;

    let opened = Zeroizing::new(
        aes(&key)?
            .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
            .map_err(|_| does_not_open())?,
    );
    <[u8; ACCOUNT_KEY_BYTES]>::try_from(opened.as_slice()).map_err(|_| {
        Error::invalid(format!(
            "an account key box opened to {} bytes, not {ACCOUNT_KEY_BYTES}",
            opened.len()
        ))
    })
}

/// `"peachy account key v3" || 0x00 || A_ed || recipient || SHA-256(link key)
/// || device_id`: the HPKE `info` of the encapsulation and the HKDF `info` of
/// the box key both.
fn hybrid_info(
    approver_signing_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    recipient_signing_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    link_key: &[u8],
    device_id: &str,
) -> Vec<u8> {
    let domain = ACCOUNT_KEY_BOX_HYBRID_DOMAIN.as_bytes();
    let mut info = Vec::with_capacity(domain.len() + 1 + 3 * 32 + device_id.len());
    info.extend_from_slice(domain);
    info.push(0);
    info.extend_from_slice(approver_signing_key);
    info.extend_from_slice(recipient_signing_key);
    info.extend_from_slice(&Sha256::digest(link_key));
    info.extend_from_slice(device_id.as_bytes());
    info
}

fn link_key_arg(key: &[u8]) -> Result<()> {
    if key.len() != crate::device_link::DEVICE_LINK_KEM_PUBLIC_KEY_BYTES {
        return Err(Error::invalid(format!(
            "a recipient_link_key must be exactly {} bytes, got {}",
            crate::device_link::DEVICE_LINK_KEM_PUBLIC_KEY_BYTES,
            key.len()
        )));
    }
    Ok(())
}

/// `HKDF(ikm, info = domain || 0x00 || A_ed || recipient || device_id)`, the
/// domain "peachy account key v1", or "… v2" for a box keyed with a link
/// secret.
fn box_key(
    ikm: &[u8],
    linked: bool,
    approver_signing_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    recipient_signing_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    device_id: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let domain = if linked {
        ACCOUNT_KEY_BOX_LINKED_DOMAIN
    } else {
        ACCOUNT_KEY_BOX_DOMAIN
    };
    let mut info =
        Vec::with_capacity(domain.len() + 1 + 2 * ED25519_PUBLIC_KEY_BYTES + device_id.len());
    info.extend_from_slice(domain.as_bytes());
    info.push(0);
    info.extend_from_slice(approver_signing_key);
    info.extend_from_slice(recipient_signing_key);
    info.extend_from_slice(device_id.as_bytes());
    hkdf32(ikm, &info)
}

/// The X25519 secret an Ed25519 seed maps to: `SHA-512(seed)[0..32]`. The
/// clamp is applied by `mul_clamped` at every use, which is the same clamp
/// RFC 7748 and RFC 8032 both specify.
fn x25519_secret(seed: &[u8; ED25519_SEED_BYTES]) -> Zeroizing<[u8; 32]> {
    let mut digest = Sha512::digest(seed);
    let mut secret = Zeroizing::new([0u8; 32]);
    for (slot, byte) in secret.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    digest.as_mut_slice().zeroize();
    secret
}

/// An Ed25519 public key as the X25519 point it maps to. Refuses a key that
/// is not a point on the curve, and a small-order one — the keys for which the
/// agreement would come out the same whatever the other side's secret.
fn montgomery(key: &[u8; ED25519_PUBLIC_KEY_BYTES], field: &str) -> Result<MontgomeryPoint> {
    let point = CompressedEdwardsY(*key)
        .decompress()
        .ok_or_else(|| Error::invalid(format!("the {field} is not a point on the curve")))?;
    if point.is_small_order() {
        return Err(Error::invalid(format!(
            "the {field} is a small-order point"
        )));
    }
    Ok(point.to_montgomery())
}

/// `X25519(secret, point)`, refusing the all-zero output a small-order point
/// forces whatever the secret.
fn shared(point: MontgomeryPoint, secret: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let out = Zeroizing::new(point.mul_clamped(*secret).to_bytes());
    if out.iter().all(|byte| *byte == 0) {
        return Err(Error::invalid(
            "the account key box agreement is all zeros: a small-order point",
        ));
    }
    Ok(out)
}

// ---- The transfer-key box -----------------------------------------------------

/// The HKDF domain of a transfer-key box's key. Its own, so a transfer box can
/// never be taken for an account-key box or the reverse.
pub const TRANSFER_KEY_DOMAIN: &str = "peachy transfer key v1";

/// The format byte of a transfer-key box.
pub const TRANSFER_KEY_BOX_VERSION: u8 = 0x01;

/// A transfer key's length: the 32-byte AES-256 key of an attachment pointer
/// (`k`, docs/sealed-messages.md §Attachment pointers).
pub const TRANSFER_KEY_BYTES: usize = 32;

/// `0x01 || E(32) || nonce(12) || ciphertext(32) || tag(16)`.
pub const TRANSFER_KEY_BOX_BYTES: usize =
    1 + X25519_BYTES + NONCE_BYTES + TRANSFER_KEY_BYTES + TAG_BYTES;

/// Seal the key of a history hand-off's document to the device it is handed
/// to (docs/sealed-messages.md §Handing history to your own new
/// device): the pointer's `kb` in place of its `k`.
///
/// `recipient_signing_key` is the recipient device's 32-byte Ed25519 public
/// key, the one the sender has just vouched for (the approval it signed, or
/// the device-list row its own-device check answered `known` or `approved`
/// on); `device_id` is that device's `devices.id`; `key` is the 32-byte
/// attachment key. Returns [`TRANSFER_KEY_BOX_BYTES`] bytes:
///
/// ```text
/// R    = recipient_signing_key as its X25519 point
/// E    = X25519(e, G) for a fresh ephemeral e
/// info = "peachy transfer key v1" || 0x00 || E || recipient_signing_key || device_id
/// k    = HKDF-SHA256(X25519(e, R), salt = <empty>, info, L = 32)
/// box  = 0x01 || E || nonce(12) || AES-256-GCM(k, nonce, key, aad = 0x01 || E)
/// ```
///
/// Only the recipient's seed opens it, so the account key alone (which a
/// removed device keeps) does not. The sender's own key is not in it: who
/// sent the hand-off is the signed note's to say, and this box says only who
/// may read it.
pub fn transfer_key_seal(
    recipient_signing_key: &[u8],
    device_id: &str,
    key: &[u8],
) -> Result<Vec<u8>> {
    // The ephemeral private key, wiped when dropped: with the recipient's
    // public key it gives one of the box's shared secrets.
    let mut ephemeral = Zeroizing::new([0u8; X25519_BYTES]);
    fill_random(&mut ephemeral[..])?;
    let mut nonce = [0u8; NONCE_BYTES];
    fill_random(&mut nonce)?;
    seal_transfer_key(recipient_signing_key, device_id, key, &ephemeral, &nonce)
}

/// [`transfer_key_seal`] with the ephemeral secret and the nonce supplied —
/// for the golden fixture and Rust tests ONLY, like [`account_key_seal_with`].
#[cfg(any(test, feature = "fixture"))]
pub fn transfer_key_seal_with(
    recipient_signing_key: &[u8],
    device_id: &str,
    key: &[u8],
    ephemeral: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    seal_transfer_key(recipient_signing_key, device_id, key, ephemeral, nonce)
}

fn seal_transfer_key(
    recipient_signing_key: &[u8],
    device_id: &str,
    key: &[u8],
    ephemeral: &[u8; X25519_BYTES],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Vec<u8>> {
    let recipient_signing_key = public_key_arg(recipient_signing_key, "recipient_signing_key")?;
    let key = transfer_key_arg(key)?;
    device_id_arg(device_id)?;
    let recipient = montgomery(&recipient_signing_key, "recipient_signing_key")?;
    let ephemeral_public = MontgomeryPoint::mul_base_clamped(*ephemeral).to_bytes();
    let box_key = transfer_box_key(
        &*shared(recipient, ephemeral)?,
        &ephemeral_public,
        &recipient_signing_key,
        device_id,
    )?;
    let aad = transfer_box_aad(&ephemeral_public);
    let sealed = aes(&box_key)?
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &key,
                aad: &aad,
            },
        )
        .map_err(|_| Error::invalid("the transfer key box could not be sealed"))?;
    let mut sealed_box = Vec::with_capacity(TRANSFER_KEY_BOX_BYTES);
    sealed_box.extend_from_slice(&aad);
    sealed_box.extend_from_slice(nonce);
    sealed_box.extend_from_slice(&sealed);
    Ok(sealed_box)
}

/// Open a transfer-key box on the device it was sealed to: `recipient_seed`
/// is THIS device's 32-byte Ed25519 seed and `device_id` its own
/// `devices.id`. Returns the 32-byte attachment key.
///
/// A box sealed to another device, to another row, or altered, "does not
/// open" — one answer for all three. So does an account-key box: the domain
/// differs.
pub fn transfer_key_open(
    recipient_seed: &[u8],
    device_id: &str,
    sealed_box: &[u8],
) -> Result<[u8; TRANSFER_KEY_BYTES]> {
    let recipient_seed = seed_arg(recipient_seed, "recipient_seed")?;
    device_id_arg(device_id)?;
    if sealed_box.len() != TRANSFER_KEY_BOX_BYTES {
        return Err(Error::invalid(format!(
            "a transfer key box must be exactly {TRANSFER_KEY_BOX_BYTES} bytes, got {}",
            sealed_box.len()
        )));
    }
    let (version, rest) = sealed_box
        .split_first()
        .ok_or_else(|| Error::invalid("a transfer key box is empty"))?;
    if *version != TRANSFER_KEY_BOX_VERSION {
        return Err(Error::invalid(format!(
            "unknown transfer key box format version 0x{version:02x}; this build reads \
             0x{TRANSFER_KEY_BOX_VERSION:02x}"
        )));
    }
    let (ephemeral_public, rest) = rest
        .split_at_checked(X25519_BYTES)
        .ok_or_else(|| Error::invalid("a transfer key box is too short"))?;
    let (nonce, sealed) = rest
        .split_at_checked(NONCE_BYTES)
        .ok_or_else(|| Error::invalid("a transfer key box is too short"))?;
    let ephemeral_public: [u8; X25519_BYTES] = ephemeral_public
        .try_into()
        .map_err(|_| Error::invalid("a transfer key box is too short"))?;

    let recipient_signing_key = signing_key_public_key(&recipient_seed[..])?;
    let box_key = transfer_box_key(
        &*shared(
            MontgomeryPoint(ephemeral_public),
            &x25519_secret(&recipient_seed),
        )?,
        &ephemeral_public,
        &recipient_signing_key,
        device_id,
    )?;
    let opened = Zeroizing::new(
        aes(&box_key)?
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: &transfer_box_aad(&ephemeral_public),
                },
            )
            .map_err(|_| {
                Error::invalid("the transfer key box does not open for this device and device id")
            })?,
    );
    <[u8; TRANSFER_KEY_BYTES]>::try_from(opened.as_slice()).map_err(|_| {
        Error::invalid(format!(
            "a transfer key box opened to {} bytes, not {TRANSFER_KEY_BYTES}",
            opened.len()
        ))
    })
}

/// `HKDF(X25519(e, R), info = "peachy transfer key v1" || 0x00 || E || R_ed
/// || device_id)`.
fn transfer_box_key(
    agreement: &[u8; 32],
    ephemeral_public: &[u8; X25519_BYTES],
    recipient_signing_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    device_id: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let domain = TRANSFER_KEY_DOMAIN.as_bytes();
    let mut info = Vec::with_capacity(
        domain.len() + 1 + X25519_BYTES + ED25519_PUBLIC_KEY_BYTES + device_id.len(),
    );
    info.extend_from_slice(domain);
    info.push(0);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_signing_key);
    info.extend_from_slice(device_id.as_bytes());
    hkdf32(agreement, &info)
}

/// `0x01 || E`: the box's head, and the AEAD's associated data.
fn transfer_box_aad(ephemeral_public: &[u8; X25519_BYTES]) -> [u8; 1 + X25519_BYTES] {
    let mut aad = [0u8; 1 + X25519_BYTES];
    aad[0] = TRANSFER_KEY_BOX_VERSION;
    aad[1..].copy_from_slice(ephemeral_public);
    aad
}

fn transfer_key_arg(key: &[u8]) -> Result<[u8; TRANSFER_KEY_BYTES]> {
    key.try_into().map_err(|_| {
        Error::invalid(format!(
            "a transfer key must be exactly {TRANSFER_KEY_BYTES} bytes, got {}",
            key.len()
        ))
    })
}

// ---- Plumbing ---------------------------------------------------------------

/// HKDF-SHA256 with an empty salt, 32 bytes out. `None` IS the empty salt:
/// RFC 5869 pads an absent salt to a hash length of zeros, and HMAC pads an
/// empty key to the same block of zeros, so the two are one PRK.
///
/// Every key derived from one input key shares that PRK, so the `info`
/// strings are the only thing that separates them. The domains in use
/// (docs/account-store.md §Key derivation domains):
///
/// | input key | `info` | derives |
/// | --- | --- | --- |
/// | account key | `"peachy account identity v1"` (nothing after) | the account identity key's seed |
/// | account key | `"peachy store v1" ‖ 0x00 ‖ id(16)` | a record's key |
/// | account key | `"peachy self note v1" ‖ 0x00 ‖ id(16)` | a self-note's key |
/// | account key | `"peachy self note v2" ‖ 0x00 ‖ id(16)` | a signed self-note's key |
/// | box agreement | `"peachy account key v1" ‖ 0x00 ‖ A ‖ B ‖ device id` | an account-key box's key |
/// | box agreement, link secret | `"peachy account key v2" ‖ 0x00 ‖ A ‖ B ‖ device id` | a linked box's key |
/// | box agreement, X-Wing secret | `"peachy account key v3" ‖ 0x00 ‖ A ‖ B ‖ SHA-256(K) ‖ device id` | a hybrid box's key |
/// | X25519(e, R) | `"peachy transfer key v1" ‖ 0x00 ‖ E ‖ R ‖ device id` | a transfer-key box's key |
/// | account key | `"peachy registration lock v1"` (nothing after; the clients derive it) | the registration lock's token |
///
/// A new domain is a new row here and in the test
/// `no_derivation_domain_is_a_prefix_of_another` (src/lib.rs, which checks
/// every label table the same way), and no domain may be a
/// prefix of another: otherwise one `info` could be another's with bytes
/// appended, and two keys would alias.
pub(crate) fn hkdf32(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, out.as_mut_slice())
        .map_err(|_| Error::invalid("HKDF refused a 32-byte output"))?;
    Ok(out)
}

fn aes(key: &[u8; 32]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).map_err(|_| Error::invalid("an AES-256 key must be 32 bytes"))
}

fn account_key_arg(key: &[u8]) -> Result<Zeroizing<[u8; ACCOUNT_KEY_BYTES]>> {
    key.try_into().map(Zeroizing::new).map_err(|_| {
        Error::invalid(format!(
            "an account_key must be exactly {ACCOUNT_KEY_BYTES} bytes, got {}",
            key.len()
        ))
    })
}

fn id_arg(id: &[u8]) -> Result<[u8; STORE_ID_BYTES]> {
    id.try_into().map_err(|_| {
        Error::invalid(format!(
            "a store id must be exactly {STORE_ID_BYTES} bytes, got {}",
            id.len()
        ))
    })
}

fn seed_arg(seed: &[u8], field: &str) -> Result<Zeroizing<[u8; ED25519_SEED_BYTES]>> {
    seed.try_into().map(Zeroizing::new).map_err(|_| {
        Error::invalid(format!(
            "a {field} must be exactly {ED25519_SEED_BYTES} bytes, got {}",
            seed.len()
        ))
    })
}

fn public_key_arg(key: &[u8], field: &str) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES]> {
    key.try_into().map_err(|_| {
        Error::invalid(format!(
            "a {field} must be exactly {ED25519_PUBLIC_KEY_BYTES} bytes, got {}",
            key.len()
        ))
    })
}

fn link_secret_arg(secret: &[u8]) -> Result<Zeroizing<[u8; LINK_KEY_BYTES]>> {
    secret.try_into().map(Zeroizing::new).map_err(|_| {
        Error::invalid(format!(
            "a link_secret must be exactly {LINK_KEY_BYTES} bytes, got {}",
            secret.len()
        ))
    })
}

fn device_id_arg(device_id: &str) -> Result<()> {
    if device_id.is_empty() {
        return Err(Error::invalid("a device_id must not be empty"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const ACCOUNT_KEY: [u8; 32] = [0xa1; 32];
    const ID: [u8; 16] = [0x11; 16];
    const OTHER_ID: [u8; 16] = [0x22; 16];
    const APPROVER_SEED: [u8; 32] = [0x11; 32];
    const RECIPIENT_SEED: [u8; 32] = [0x33; 32];
    const DEVICE_ID: &str = "0f8e2b1c-6a4d-4e3f-9b2a-7c5d1e0f3a9b";

    fn public(seed: &[u8; 32]) -> [u8; 32] {
        signing_key_public_key(seed).expect("a public half")
    }

    #[test]
    fn padding_fills_to_the_next_block_and_always_adds_a_byte() {
        assert_eq!(pad(&[]).len(), 256);
        assert_eq!(pad(&[7u8; 255]).len(), 256);
        assert_eq!(pad(&[7u8; 256]).len(), 512);
        assert_eq!(pad(&[7u8; 511]).len(), 512);
        assert_eq!(pad(&[7u8; 512]).len(), 768);
        let padded = pad(b"hi");
        assert_eq!(&padded[..3], b"hi\x80");
        assert!(padded[3..].iter().all(|b| *b == 0));
        // A plaintext that itself ends in zeros and 0x80 survives: only the
        // LAST 0x80 before the trailing zeros is the marker.
        let tricky = [0x80u8, 0, 0, 0x80, 0];
        let mut padded = pad(&tricky);
        unpad(&mut padded).expect("round trip");
        assert_eq!(padded, tricky);
    }

    #[test]
    fn unpad_refuses_anything_that_is_not_marker_then_zeros() {
        assert!(unpad(&mut vec![0u8; 256]).is_err());
        assert!(unpad(&mut vec![1, 2, 3, 0, 0]).is_err());
        assert!(unpad(&mut Vec::new()).is_err());
        let mut padded = vec![1, 0x80, 0];
        unpad(&mut padded).expect("ok");
        assert_eq!(padded, vec![1]);
    }

    #[test]
    fn a_record_round_trips_at_every_boundary() {
        for len in [0usize, 1, 255, 256, 257, 1000, MAX_STORE_PLAINTEXT_BYTES] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let value = store_seal(&ACCOUNT_KEY, &ID, &plaintext).expect("seals");
            assert_eq!(value[0], STORE_FORMAT_VERSION);
            assert_eq!((value.len() - 29) % 256, 0, "len {len}");
            assert_eq!(
                store_open(&ACCOUNT_KEY, &ID, &value).expect("opens"),
                plaintext
            );
        }
        let manifest = store_seal(&ACCOUNT_KEY, &MANIFEST_ID, b"{}").expect("seals");
        assert_eq!(
            store_open(&ACCOUNT_KEY, &MANIFEST_ID, &manifest).expect("opens"),
            b"{}"
        );
    }

    #[test]
    fn two_seals_of_one_record_differ() {
        let one = store_seal(&ACCOUNT_KEY, &ID, b"same").expect("seals");
        let two = store_seal(&ACCOUNT_KEY, &ID, b"same").expect("seals");
        assert_ne!(one, two, "a fresh nonce every time");
    }

    #[test]
    fn a_record_refuses_every_wrong_input() {
        let value = store_seal_with(&ACCOUNT_KEY, &ID, b"hello", &[9u8; 12]).expect("seals");

        let wrong_id = store_open(&ACCOUNT_KEY, &OTHER_ID, &value).expect_err("wrong id");
        assert!(wrong_id.to_string().contains("does not open"), "{wrong_id}");
        let wrong_key = store_open(&[0xa2; 32], &ID, &value).expect_err("wrong key");
        assert!(
            wrong_key.to_string().contains("does not open"),
            "{wrong_key}"
        );

        let mut tampered = value.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let err = store_open(&ACCOUNT_KEY, &ID, &tampered).expect_err("tampered");
        assert!(err.to_string().contains("does not open"), "{err}");

        let mut bad_version = value.clone();
        bad_version[0] = 0x02;
        let err = store_open(&ACCOUNT_KEY, &ID, &bad_version).expect_err("version");
        assert!(err.to_string().contains("format version 0x02"), "{err}");

        let err = store_open(&ACCOUNT_KEY, &ID, &value[..value.len() - 1]).expect_err("short");
        assert!(err.to_string().contains("too short"), "{err}");

        let err = store_open(&ACCOUNT_KEY, &ID[..15], &value).expect_err("15-byte id");
        assert!(
            err.to_string().contains("exactly 16 bytes, got 15"),
            "{err}"
        );
        let err = store_seal(&ACCOUNT_KEY, &[0u8; 17], b"x").expect_err("17-byte id");
        assert!(
            err.to_string().contains("exactly 16 bytes, got 17"),
            "{err}"
        );
        let err = store_seal(&ACCOUNT_KEY[..31], &ID, b"x").expect_err("short key");
        assert!(err.to_string().contains("account_key"), "{err}");

        let err = store_seal(&ACCOUNT_KEY, &ID, &vec![0u8; MAX_STORE_PLAINTEXT_BYTES + 1])
            .expect_err("too big");
        assert!(err.to_string().contains("at most 65536"), "{err}");
    }

    #[test]
    fn the_manifest_has_its_own_larger_cap_and_records_keep_theirs() {
        // A record past 65,536 bytes is refused; the manifest is not, up to
        // its own cap, and then it is.
        let big = vec![b'a'; MAX_STORE_PLAINTEXT_BYTES + 1];
        assert!(store_seal(&ACCOUNT_KEY, &ID, &big).is_err());
        let sealed = store_seal(&ACCOUNT_KEY, &MANIFEST_ID, &big).expect("a manifest past 64 KiB");
        assert_eq!(
            store_open(&ACCOUNT_KEY, &MANIFEST_ID, &sealed).expect("opens"),
            big
        );
        let at_cap = vec![b'a'; MAX_MANIFEST_PLAINTEXT_BYTES];
        let sealed = store_seal(&ACCOUNT_KEY, &MANIFEST_ID, &at_cap).expect("at the cap");
        assert!(
            sealed.len() <= 512 * 1024,
            "under the server's manifest limit"
        );
        let err = store_seal(
            &ACCOUNT_KEY,
            &MANIFEST_ID,
            &[at_cap.as_slice(), b"a"].concat(),
        )
        .expect_err("past the cap");
        assert!(err.to_string().contains("at most 360000"), "{err}");
        // Notes keep the record cap.
        let err = note_seal_with(&ACCOUNT_KEY, &ID, &big, &[0; NONCE_BYTES])
            .expect_err("a note past 64 KiB");
        assert!(err.to_string().contains("at most 65536"), "{err}");
    }

    #[test]
    fn a_value_that_opens_but_is_not_padded_is_refused() {
        // Sealed by hand under the right key with no padding at all: the AEAD
        // is happy and the module is not.
        let key = record_key(&ACCOUNT_KEY, &ID).expect("a key");
        let nonce = [3u8; 12];
        let sealed = aes(&key)
            .expect("aes")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &[0x41u8; 256],
                    aad: &ID,
                },
            )
            .expect("encrypts");
        let mut value = vec![STORE_FORMAT_VERSION];
        value.extend_from_slice(&nonce);
        value.extend_from_slice(&sealed);
        let err = store_open(&ACCOUNT_KEY, &ID, &value).expect_err("unpadded");
        assert!(err.to_string().contains("not padded"), "{err}");
    }

    #[test]
    fn record_keys_differ_per_id_and_per_account() {
        let a = record_key(&ACCOUNT_KEY, &ID).expect("k");
        assert_ne!(a, record_key(&ACCOUNT_KEY, &OTHER_ID).expect("k"));
        assert_ne!(a, record_key(&[0xa2; 32], &ID).expect("k"));
        assert_ne!(a, record_key(&ACCOUNT_KEY, &MANIFEST_ID).expect("k"));
    }

    #[test]
    fn a_box_round_trips_and_is_93_bytes() {
        let key = generate_account_key().expect("a key");
        let sealed = account_key_seal(&APPROVER_SEED, &public(&RECIPIENT_SEED), DEVICE_ID, &key)
            .expect("seals");
        assert_eq!(sealed.len(), 93);
        assert_eq!(ACCOUNT_KEY_BOX_BYTES, 93);
        assert_eq!(
            account_key_open(&RECIPIENT_SEED, &public(&APPROVER_SEED), DEVICE_ID, &sealed)
                .expect("opens"),
            key
        );
    }

    #[test]
    fn a_box_opens_only_for_its_approver_its_recipient_and_its_row() {
        let sealed = account_key_seal(
            &APPROVER_SEED,
            &public(&RECIPIENT_SEED),
            DEVICE_ID,
            &ACCOUNT_KEY,
        )
        .expect("seals");

        let checks: [(&[u8; 32], [u8; 32], &str); 3] = [
            // The server's substitution: claim a different approver.
            (&RECIPIENT_SEED, public(&[0x44; 32]), DEVICE_ID),
            // Replayed onto another device row.
            (&RECIPIENT_SEED, public(&APPROVER_SEED), "another-device"),
            // Opened by somebody else's device.
            (&[0x55; 32], public(&APPROVER_SEED), DEVICE_ID),
        ];
        for (seed, approver, device) in checks {
            let err = account_key_open(seed, &approver, device, &sealed).expect_err("refused");
            assert!(err.to_string().contains("does not open"), "{err}");
        }

        let mut tampered = sealed.clone();
        tampered[5] ^= 1; // inside E, which is the AEAD's associated data
        assert!(account_key_open(
            &RECIPIENT_SEED,
            &public(&APPROVER_SEED),
            DEVICE_ID,
            &tampered
        )
        .is_err());

        let mut bad_version = sealed.clone();
        bad_version[0] = 0;
        let err = account_key_open(
            &RECIPIENT_SEED,
            &public(&APPROVER_SEED),
            DEVICE_ID,
            &bad_version,
        )
        .expect_err("version");
        assert!(err.to_string().contains("format version 0x00"), "{err}");

        let err = account_key_open(
            &RECIPIENT_SEED,
            &public(&APPROVER_SEED),
            DEVICE_ID,
            &sealed[..92],
        )
        .expect_err("short");
        assert!(err.to_string().contains("exactly 93 bytes"), "{err}");

        let err = account_key_open(&RECIPIENT_SEED, &public(&APPROVER_SEED), "", &sealed)
            .expect_err("empty id");
        assert!(err.to_string().contains("device_id"), "{err}");
    }

    #[test]
    fn a_box_without_the_approvers_secret_does_not_open() {
        // What a server holding only PUBLIC keys can build: the ephemeral half
        // right, the static half from a key it made up. It does not open under
        // the approver the recipient drew a code for.
        let forged = account_key_seal(
            &[0x77; 32],
            &public(&RECIPIENT_SEED),
            DEVICE_ID,
            &ACCOUNT_KEY,
        )
        .expect("seals");
        assert!(
            account_key_open(&RECIPIENT_SEED, &public(&APPROVER_SEED), DEVICE_ID, &forged).is_err()
        );
    }

    #[test]
    fn a_small_order_or_off_curve_key_is_refused() {
        // The identity point (y = 1) is small-order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let err = account_key_seal(&APPROVER_SEED, &identity, DEVICE_ID, &ACCOUNT_KEY)
            .expect_err("small order");
        assert!(err.to_string().contains("small-order"), "{err}");

        // y = 2 is not on the curve (x^2 would be a non-square).
        let mut off_curve = [0u8; 32];
        off_curve[0] = 2;
        let err = account_key_seal(&APPROVER_SEED, &off_curve, DEVICE_ID, &ACCOUNT_KEY)
            .expect_err("off curve");
        assert!(err.to_string().contains("recipient_signing_key"), "{err}");

        let err = account_key_open(&RECIPIENT_SEED, &identity, DEVICE_ID, &[1u8; 93])
            .expect_err("small order approver");
        assert!(err.to_string().contains("approver_signing_key"), "{err}");
    }

    #[test]
    fn the_deterministic_seal_is_deterministic() {
        let e = [0x55u8; 32];
        let n = [0x66u8; 12];
        let one = account_key_seal_with(
            &APPROVER_SEED,
            &public(&RECIPIENT_SEED),
            DEVICE_ID,
            &ACCOUNT_KEY,
            &e,
            &n,
        )
        .expect("seals");
        let two = account_key_seal_with(
            &APPROVER_SEED,
            &public(&RECIPIENT_SEED),
            DEVICE_ID,
            &ACCOUNT_KEY,
            &e,
            &n,
        )
        .expect("seals");
        assert_eq!(one, two);
        assert_eq!(&one[1..33], MontgomeryPoint::mul_base_clamped(e).as_bytes());
    }

    const NOTE_NOW: i64 = 1_800_000_000_000;
    const SENDER: &str = "dev-phone";

    #[test]
    fn a_signed_note_opens_only_for_its_sender_and_within_the_window() {
        let phone = public(&APPROVER_SEED);
        let note = note_seal_signed(&ACCOUNT_KEY, &ID, b"{}", SENDER, NOTE_NOW, &APPROVER_SEED)
            .expect("seals");
        assert_eq!(note.first(), Some(&NOTE_SIGNED_VERSION));
        assert_eq!(
            note_sender(&ACCOUNT_KEY, &ID, &note).expect("a sender"),
            SENDER
        );
        assert_eq!(
            note_open_signed(&ACCOUNT_KEY, &ID, &note, SENDER, &phone, NOTE_NOW).expect("opens"),
            b"{}"
        );

        // Another device's key, another claimed sender: refused.
        let err = note_open_signed(
            &ACCOUNT_KEY,
            &ID,
            &note,
            SENDER,
            &public(&RECIPIENT_SEED),
            NOTE_NOW,
        )
        .expect_err("wrong key");
        assert!(err.to_string().contains("does not verify"), "{err}");
        let err = note_open_signed(&ACCOUNT_KEY, &ID, &note, "dev-laptop", &phone, NOTE_NOW)
            .expect_err("wrong sender");
        assert!(err.to_string().contains("names device"), "{err}");

        // The window: seven days back, ten minutes ahead.
        assert!(note_open_signed(
            &ACCOUNT_KEY,
            &ID,
            &note,
            SENDER,
            &phone,
            NOTE_NOW + NOTE_MAX_AGE_MS
        )
        .is_ok());
        let err = note_open_signed(
            &ACCOUNT_KEY,
            &ID,
            &note,
            SENDER,
            &phone,
            NOTE_NOW + NOTE_MAX_AGE_MS + 1,
        )
        .expect_err("stale");
        assert!(err.to_string().contains("stale"), "{err}");
        assert!(note_open_signed(
            &ACCOUNT_KEY,
            &ID,
            &note,
            SENDER,
            &phone,
            NOTE_NOW - NOTE_MAX_AHEAD_MS
        )
        .is_ok());
        let err = note_open_signed(
            &ACCOUNT_KEY,
            &ID,
            &note,
            SENDER,
            &phone,
            NOTE_NOW - NOTE_MAX_AHEAD_MS - 1,
        )
        .expect_err("ahead");
        assert!(err.to_string().contains("ahead"), "{err}");

        // Under another id, or as a record: does not open.
        assert!(note_sender(&ACCOUNT_KEY, &OTHER_ID, &note).is_err());
        assert!(store_open(&ACCOUNT_KEY, &ID, &note).is_err());
    }

    #[test]
    fn an_unsigned_note_names_no_sender() {
        let old = note_seal_with(&ACCOUNT_KEY, &ID, b"{}", &[0; NONCE_BYTES]).expect("seals");
        let err = note_sender(&ACCOUNT_KEY, &ID, &old).expect_err("unsigned");
        assert!(err.to_string().contains("unsigned"), "{err}");
        let err = note_open_signed(
            &ACCOUNT_KEY,
            &ID,
            &old,
            SENDER,
            &public(&APPROVER_SEED),
            NOTE_NOW,
        )
        .expect_err("unsigned");
        assert!(err.to_string().contains("unsigned"), "{err}");
    }

    #[test]
    fn a_holder_of_the_account_key_cannot_sign_as_another_device() {
        // A holder of the account key can seal a note naming the phone, but
        // only with its own key, which the phone's does not verify.
        let forged = note_seal_signed(&ACCOUNT_KEY, &ID, b"{}", SENDER, NOTE_NOW, &[0x77; 32])
            .expect("seals");
        assert_eq!(
            note_sender(&ACCOUNT_KEY, &ID, &forged).expect("claims"),
            SENDER
        );
        assert!(note_open_signed(
            &ACCOUNT_KEY,
            &ID,
            &forged,
            SENDER,
            &public(&APPROVER_SEED),
            NOTE_NOW
        )
        .is_err());
    }

    #[test]
    fn a_signed_note_refuses_bad_arguments() {
        let err = note_seal_signed(&ACCOUNT_KEY, &ID, b"", "", NOTE_NOW, &APPROVER_SEED)
            .expect_err("empty");
        assert!(err.to_string().contains("sender_device_id"), "{err}");
        let long = "d".repeat(256);
        let err = note_seal_signed(&ACCOUNT_KEY, &ID, b"", &long, NOTE_NOW, &APPROVER_SEED)
            .expect_err("long");
        assert!(err.to_string().contains("at most 255"), "{err}");
        let err = note_seal_signed(&ACCOUNT_KEY, &ID, b"", SENDER, -1, &APPROVER_SEED)
            .expect_err("negative");
        assert!(err.to_string().contains("negative"), "{err}");
        let err = note_seal_signed(
            &ACCOUNT_KEY,
            &ID,
            b"",
            SENDER,
            NOTE_NOW,
            &APPROVER_SEED[..31],
        )
        .expect_err("seed");
        assert!(err.to_string().contains("device_seed"), "{err}");
        let big = vec![0u8; MAX_STORE_PLAINTEXT_BYTES];
        let err = note_seal_signed(&ACCOUNT_KEY, &ID, &big, SENDER, NOTE_NOW, &APPROVER_SEED)
            .expect_err("big");
        assert!(
            err.to_string().contains("plaintext must be at most"),
            "{err}"
        );
        let fits = vec![0u8; MAX_STORE_PLAINTEXT_BYTES - NOTE_SIGNED_OVERHEAD - SENDER.len()];
        let note = note_seal_signed(&ACCOUNT_KEY, &ID, &fits, SENDER, NOTE_NOW, &APPROVER_SEED)
            .expect("fits");
        assert_eq!(
            note_open_signed(
                &ACCOUNT_KEY,
                &ID,
                &note,
                SENDER,
                &public(&APPROVER_SEED),
                NOTE_NOW
            )
            .expect("opens")
            .len(),
            fits.len()
        );
    }

    const QR_LINK_KEY: [u8; 32] = [0x5e; 32];

    #[test]
    fn a_linked_box_opens_only_with_its_secret() {
        let sealed = account_key_seal_linked(
            &APPROVER_SEED,
            &public(&RECIPIENT_SEED),
            DEVICE_ID,
            &ACCOUNT_KEY,
            &QR_LINK_KEY,
        )
        .expect("a box");
        assert_eq!(sealed.len(), ACCOUNT_KEY_BOX_BYTES);
        assert_eq!(sealed.first(), Some(&ACCOUNT_KEY_BOX_LINKED_VERSION));
        let approver = public(&APPROVER_SEED);
        let opened = account_key_accept(
            &RECIPIENT_SEED,
            &approver,
            DEVICE_ID,
            &sealed,
            &QR_LINK_KEY,
            &[],
            false,
        )
        .expect("opens with the secret");
        assert_eq!(opened, ACCOUNT_KEY);
        // Another secret, no secret, or the plain opener: refused.
        assert!(account_key_accept(
            &RECIPIENT_SEED,
            &approver,
            DEVICE_ID,
            &sealed,
            &[0x5f; 32],
            &[],
            true
        )
        .is_err());
        let err = account_key_accept(
            &RECIPIENT_SEED,
            &approver,
            DEVICE_ID,
            &sealed,
            &[],
            &approver,
            true,
        )
        .expect_err("no secret");
        assert!(err.to_string().contains("QR code"), "{err}");
        assert!(account_key_open(&RECIPIENT_SEED, &approver, DEVICE_ID, &sealed).is_err());
    }

    #[test]
    fn a_plain_box_needs_a_confirmed_approver_or_the_local_switch() {
        let approver = public(&APPROVER_SEED);
        let sealed = account_key_seal(
            &APPROVER_SEED,
            &public(&RECIPIENT_SEED),
            DEVICE_ID,
            &ACCOUNT_KEY,
        )
        .expect("a box");
        let err = account_key_accept(
            &RECIPIENT_SEED,
            &approver,
            DEVICE_ID,
            &sealed,
            &QR_LINK_KEY,
            &[],
            false,
        )
        .expect_err("nobody confirmed it");
        assert!(err.to_string().contains("did not confirm"), "{err}");
        let err = account_key_accept(
            &RECIPIENT_SEED,
            &approver,
            DEVICE_ID,
            &sealed,
            &[],
            &public(&[0x44; 32]),
            false,
        )
        .expect_err("another approver was confirmed");
        assert!(err.to_string().contains("did not confirm"), "{err}");
        assert_eq!(
            account_key_accept(
                &RECIPIENT_SEED,
                &approver,
                DEVICE_ID,
                &sealed,
                &[],
                &approver,
                false
            )
            .expect("the confirmed approver"),
            ACCOUNT_KEY
        );
        assert_eq!(
            account_key_accept(
                &RECIPIENT_SEED,
                &approver,
                DEVICE_ID,
                &sealed,
                &[],
                &[],
                true
            )
            .expect("the local switch"),
            ACCOUNT_KEY
        );
    }

    const LINK_SEED: [u8; 32] = [0x5a; 32];

    fn hybrid_box() -> Vec<u8> {
        let link_key =
            crate::device_link::device_link_kem_public_key(&LINK_SEED).expect("a link key");
        account_key_seal_hybrid(
            &APPROVER_SEED,
            &public(&RECIPIENT_SEED),
            &link_key,
            DEVICE_ID,
            &ACCOUNT_KEY,
        )
        .expect("a hybrid box")
    }

    #[test]
    fn a_hybrid_box_round_trips_for_its_confirmed_approver() {
        let approver = public(&APPROVER_SEED);
        let sealed = hybrid_box();
        assert_eq!(sealed.len(), ACCOUNT_KEY_BOX_HYBRID_BYTES);
        assert_eq!(sealed.len(), 1213);
        assert_eq!(sealed[0], ACCOUNT_KEY_BOX_HYBRID_VERSION);
        assert_eq!(
            account_key_accept_hybrid(
                &RECIPIENT_SEED,
                &approver,
                DEVICE_ID,
                &sealed,
                &LINK_SEED,
                &approver,
                false,
            )
            .expect("opens"),
            ACCOUNT_KEY
        );
        // The local switch never opens it without the person's pick: it
        // opens only a version-1 box.
        assert!(account_key_accept_hybrid(
            &RECIPIENT_SEED,
            &approver,
            DEVICE_ID,
            &sealed,
            &LINK_SEED,
            &[],
            true,
        )
        .is_err());
    }

    #[test]
    fn a_hybrid_box_needs_the_link_key_seed_and_every_bound_input() {
        let approver = public(&APPROVER_SEED);
        let sealed = hybrid_box();
        let accept = |seed: &[u8], approver_key: &[u8], device: &str, bytes: &[u8]| {
            account_key_accept_hybrid(
                seed,
                approver_key,
                device,
                bytes,
                &LINK_SEED,
                approver_key,
                false,
            )
        };
        // Without the link key's seed: the X25519 halves alone do not open it.
        let err = account_key_accept_hybrid(
            &RECIPIENT_SEED,
            &approver,
            DEVICE_ID,
            &sealed,
            &[],
            &approver,
            false,
        )
        .expect_err("no link key");
        assert!(err.to_string().contains("posted none"), "{err}");
        // Another link key.
        assert!(account_key_accept_hybrid(
            &RECIPIENT_SEED,
            &approver,
            DEVICE_ID,
            &sealed,
            &[0x5b; 32],
            &approver,
            false,
        )
        .is_err());
        // Another recipient, approver or row.
        assert!(accept(&[0x34; 32], &approver, DEVICE_ID, &sealed).is_err());
        assert!(accept(&RECIPIENT_SEED, &public(&[0x12; 32]), DEVICE_ID, &sealed).is_err());
        assert!(accept(&RECIPIENT_SEED, &approver, "another-row", &sealed).is_err());
        // Any flipped bit: in E, in the encapsulation, in the nonce or in the
        // ciphertext.
        for at in [1usize, 40, 1100, 1160, 1170, 1212] {
            let mut bent = sealed.clone();
            bent[at] ^= 0x01;
            assert!(
                accept(&RECIPIENT_SEED, &approver, DEVICE_ID, &bent).is_err(),
                "byte {at}"
            );
        }
        // A short one.
        assert!(accept(&RECIPIENT_SEED, &approver, DEVICE_ID, &sealed[..1212]).is_err());
        // An unconfirmed approver.
        let err = account_key_accept_hybrid(
            &RECIPIENT_SEED,
            &approver,
            DEVICE_ID,
            &sealed,
            &LINK_SEED,
            &[],
            false,
        )
        .expect_err("nobody confirmed it");
        assert!(err.to_string().contains("did not confirm"), "{err}");
    }

    #[test]
    fn an_x25519_only_box_from_a_confirmed_approver_is_refused() {
        let approver = public(&APPROVER_SEED);
        let plain = account_key_seal(
            &APPROVER_SEED,
            &public(&RECIPIENT_SEED),
            DEVICE_ID,
            &ACCOUNT_KEY,
        )
        .expect("a box");
        let err = account_key_accept_hybrid(
            &RECIPIENT_SEED,
            &approver,
            DEVICE_ID,
            &plain,
            &LINK_SEED,
            &approver,
            false,
        )
        .expect_err("refused");
        assert!(err.to_string().contains("X25519-only"), "{err}");
        // A test server's own approvals still open under the local switch.
        assert_eq!(
            account_key_accept_hybrid(
                &RECIPIENT_SEED,
                &approver,
                DEVICE_ID,
                &plain,
                &[],
                &[],
                true,
            )
            .expect("the local switch"),
            ACCOUNT_KEY
        );
        // The removed QR code's box never opens here.
        let linked = account_key_seal_linked(
            &APPROVER_SEED,
            &public(&RECIPIENT_SEED),
            DEVICE_ID,
            &ACCOUNT_KEY,
            &QR_LINK_KEY,
        )
        .expect("a linked box");
        assert!(account_key_accept_hybrid(
            &RECIPIENT_SEED,
            &approver,
            DEVICE_ID,
            &linked,
            &LINK_SEED,
            &approver,
            true,
        )
        .is_err());
    }

    #[test]
    fn the_x25519_only_doors_never_open_a_hybrid_box() {
        let approver = public(&APPROVER_SEED);
        let sealed = hybrid_box();
        assert!(account_key_open(&RECIPIENT_SEED, &approver, DEVICE_ID, &sealed).is_err());
        assert!(account_key_accept(
            &RECIPIENT_SEED,
            &approver,
            DEVICE_ID,
            &sealed,
            &[],
            &approver,
            true,
        )
        .is_err());
    }

    #[test]
    fn a_hybrid_box_refuses_a_link_key_of_the_wrong_length() {
        let err = account_key_seal_hybrid(
            &APPROVER_SEED,
            &public(&RECIPIENT_SEED),
            &[7u8; 1215],
            DEVICE_ID,
            &ACCOUNT_KEY,
        )
        .expect_err("not a link key");
        assert!(err.to_string().contains("1216"), "{err}");
    }

    const TRANSFER_KEY: [u8; 32] = [0x7c; 32];

    #[test]
    fn a_transfer_key_box_opens_only_on_its_device_and_row() {
        let sealed =
            transfer_key_seal(&public(&RECIPIENT_SEED), DEVICE_ID, &TRANSFER_KEY).expect("box");
        assert_eq!(sealed.len(), TRANSFER_KEY_BOX_BYTES);
        assert_eq!(sealed.len(), 93);
        assert_eq!(sealed[0], TRANSFER_KEY_BOX_VERSION);
        assert_eq!(
            transfer_key_open(&RECIPIENT_SEED, DEVICE_ID, &sealed).expect("opens"),
            TRANSFER_KEY
        );
        let does_not_open = "does not open for this device and device id";
        // Another device: the account key it may hold is no help.
        let err = transfer_key_open(&APPROVER_SEED, DEVICE_ID, &sealed).expect_err("wrong seed");
        assert!(err.to_string().contains(does_not_open), "{err}");
        // The same key under another row.
        let err = transfer_key_open(&RECIPIENT_SEED, "another-row", &sealed).expect_err("row");
        assert!(err.to_string().contains(does_not_open), "{err}");
        // E is half the agreement and the associated data.
        let mut tampered = sealed.clone();
        tampered[1] ^= 0x01;
        assert!(transfer_key_open(&RECIPIENT_SEED, DEVICE_ID, &tampered).is_err());
        let mut tampered = sealed.clone();
        tampered[92] ^= 0x01;
        let err = transfer_key_open(&RECIPIENT_SEED, DEVICE_ID, &tampered).expect_err("tag");
        assert!(err.to_string().contains(does_not_open), "{err}");
        let mut bad_version = sealed.clone();
        bad_version[0] = 0x02;
        let err = transfer_key_open(&RECIPIENT_SEED, DEVICE_ID, &bad_version).expect_err("v");
        assert!(err.to_string().contains("0x02"), "{err}");
        let err = transfer_key_open(&RECIPIENT_SEED, DEVICE_ID, &sealed[..92]).expect_err("len");
        assert!(
            err.to_string().contains("exactly 93 bytes, got 92"),
            "{err}"
        );
        assert!(transfer_key_open(&RECIPIENT_SEED, "", &sealed).is_err());
        // Two seals of one key differ.
        assert_ne!(
            sealed,
            transfer_key_seal(&public(&RECIPIENT_SEED), DEVICE_ID, &TRANSFER_KEY).expect("box")
        );
    }

    #[test]
    fn a_transfer_key_box_and_an_account_key_box_never_open_as_each_other() {
        // The same length and the same leading byte, and still nothing
        // crosses: the domains differ.
        let transfer =
            transfer_key_seal(&public(&RECIPIENT_SEED), DEVICE_ID, &TRANSFER_KEY).expect("box");
        assert!(account_key_open(
            &RECIPIENT_SEED,
            &public(&APPROVER_SEED),
            DEVICE_ID,
            &transfer
        )
        .is_err());
        assert!(account_key_accept(
            &RECIPIENT_SEED,
            &public(&APPROVER_SEED),
            DEVICE_ID,
            &transfer,
            &[],
            &public(&APPROVER_SEED),
            false,
        )
        .is_err());
        let account = account_key_seal(
            &APPROVER_SEED,
            &public(&RECIPIENT_SEED),
            DEVICE_ID,
            &ACCOUNT_KEY,
        )
        .expect("box");
        assert_eq!(account.len(), transfer.len());
        let err = transfer_key_open(&RECIPIENT_SEED, DEVICE_ID, &account).expect_err("crossed");
        assert!(
            err.to_string()
                .contains("does not open for this device and device id"),
            "{err}"
        );
    }

    #[test]
    fn a_transfer_key_box_refuses_bad_arguments() {
        let recipient = public(&RECIPIENT_SEED);
        let err = transfer_key_seal(&recipient, DEVICE_ID, &[1u8; 16]).expect_err("short key");
        assert!(
            err.to_string().contains("exactly 32 bytes, got 16"),
            "{err}"
        );
        let err = transfer_key_seal(&recipient, DEVICE_ID, &[1u8; 33]).expect_err("long key");
        assert!(
            err.to_string().contains("exactly 32 bytes, got 33"),
            "{err}"
        );
        assert!(transfer_key_seal(&recipient, "", &TRANSFER_KEY).is_err());
        assert!(transfer_key_seal(&recipient[..31], DEVICE_ID, &TRANSFER_KEY).is_err());
        // The identity point is small-order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let err = transfer_key_seal(&identity, DEVICE_ID, &TRANSFER_KEY).expect_err("small");
        assert!(err.to_string().contains("small-order"), "{err}");
        let sealed = transfer_key_seal(&recipient, DEVICE_ID, &TRANSFER_KEY).expect("box");
        assert!(transfer_key_open(&RECIPIENT_SEED[..31], DEVICE_ID, &sealed).is_err());
    }

    #[test]
    fn the_deterministic_transfer_seal_is_deterministic() {
        let one = transfer_key_seal_with(
            &public(&RECIPIENT_SEED),
            DEVICE_ID,
            &TRANSFER_KEY,
            &[0x5e; 32],
            &[0x66; 12],
        )
        .expect("box");
        let two = transfer_key_seal_with(
            &public(&RECIPIENT_SEED),
            DEVICE_ID,
            &TRANSFER_KEY,
            &[0x5e; 32],
            &[0x66; 12],
        )
        .expect("box");
        assert_eq!(one, two);
        assert_eq!(
            transfer_key_open(&RECIPIENT_SEED, DEVICE_ID, &one).expect("opens"),
            TRANSFER_KEY
        );
    }
}
