// SPDX-License-Identifier: MIT
//! The `pdc1` device credential, as an MLS leaf credential.
//!
//! A Peachy device credential is a compact three-part ASCII token minted by the
//! server (the server's credential issuer, docs/identity.md §Format):
//!
//! ```text
//! pdc1.<base64url(canonical payload JSON)>.<base64url(64-byte Ed25519 sig)>
//! ```
//!
//! The payload is `{v,kid,actor_id,device_id,device_key,account_key,account_sig,iat,exp}`
//! in exactly that key order, and **the signed bytes are the encoded payload as it
//! arrived**, never a re-serialization of the parsed object. This module
//! therefore keeps the raw middle segment's decoded bytes beside the parsed
//! struct and hands *those* to Ed25519. A verifier that re-serializes is a
//! verifier whose signatures depend on a JSON library's key ordering, which is
//! how a signature scheme rots.
//!
//! ## One spelling
//!
//! The arrived bytes must also BE the canonical spelling of what they say:
//! the payload exactly as `canonicalPayload` writes it (that key order, no
//! whitespace, no escapes, `device_key` and the account fields in padded
//! standard base64), both segments in unpadded base64url, and a `kid` of
//! exactly eight lowercase hex characters. [`DeviceCredential::parse`]
//! rebuilds the token from what it read and refuses anything that is not
//! byte for byte the same as [`CredentialRejection::Malformed`]. The
//! signature is still checked over the bytes as they arrived; the rebuild
//! only proves there was one way to write them. It is what makes a
//! credential's length a function of its fields: were any spelling read,
//! the issuer could give each device a token of its own length, and the
//! growth of every renewal and leaf rotation would name the device that made
//! it (docs/identity.md §Format).
//!
//! ## One format, and nothing beside it
//!
//! `pdc1` is the only prefix this build reads. Any other prefix is refused as
//! [`CredentialRejection::Malformed`], however well signed. It is never read
//! as a person: there is no second reading of a
//! token, so a token this build cannot fully account for is not a leaf.
//!
//! The payload is read the same way. It is the nine fields and nothing else
//! (`deny_unknown_fields`): a `pdc1` carrying an extra key — anything a
//! newer issuer invents — is malformed
//! rather than quietly accepted as a device with the extra claim ignored. A
//! new field arrives with a new prefix, which is what the prefix is for
//! (docs/identity.md §Format).
//!
//! ## Why the leaf credential is `BasicCredential`-shaped
//!
//! RFC 9420 gives two credential types, `basic` (0x0001) and `x509` (0x0002),
//! and a registry for more. Peachy ships the token inside a *basic* credential's
//! `identity` field rather than registering a custom credential type, and that
//! is a deliberate trade:
//!
//! - A custom type is the semantically honest answer, but an unknown credential
//!   type is a hard interop failure in every other implementation, and the whole
//!   direction of travel (docs/mls-core.md) is towards a group whose
//!   members are not all running our code.
//! - `basic` says only "here are some bytes that identify the leaf", which is
//!   exactly what the token is. Nothing is smuggled: the bytes are a
//!   self-describing, versioned, signed artefact, and a reader that does not
//!   understand `pdc1` learns nothing it could have misused.
//!
//! The cost is that the *type* no longer warns a stranger that these bytes need
//! checking, so [`crate::identity::PeachyIdentityProvider`] is the only thing
//! that makes the credential mean anything, and every leaf on the way in must
//! go through it. `Peachy` never treats a leaf as identified because it parsed.
//!
//! ## Sizes
//!
//! A classical credential runs about 330 bytes: the payload JSON is
//! ~200 (a UUID actor id, a UUID device id and a 44-char base64 key), base64url
//! adds a third, and the signature segment is a fixed 86. [`MAX_TOKEN_BYTES`] is
//! set well above that, at a size that still admits a post-quantum `device_key`
//! — ML-KEM key packages measured about 9.5x the size of classical ones, and
//! an ML-DSA-65 public key is 1,952 bytes, so
//! a PQ-era payload lands near 3 KB encoded. The limit exists to bound the work
//! a malformed leaf can cause, not to express a format rule.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{CredentialRejection, Error, Result};

/// The token prefix of a device credential — one of a person's phones,
/// laptops or browsers. The only prefix this build reads.
pub const TOKEN_PREFIX: &str = "pdc1";

/// The payload version a [`TOKEN_PREFIX`] token carries.
pub const CREDENTIAL_VERSION: u8 = 1;

/// The longest actor or device id this build reads, in bytes.
pub const MAX_ID_BYTES: usize = 64;

/// Whether `id` is an actor or device id this build accepts: 1 to
/// [`MAX_ID_BYTES`] bytes, each an ASCII letter, digit, `.`, `_` or `-`.
///
/// The server issues ids as lowercase UUIDs, and every test id
/// (`device-ada-laptop`) fits too. What the rule keeps out is anything that
/// could mean something to a reader of a list of ids: a line break or a NUL
/// (a list joined as text), `#` (the long form
/// [`crate::group::Client::own_sibling_leaves`] writes for a device under an
/// unexpected key), `/` (the device-link QR's separator), whitespace and
/// every other byte. An id is a name for a row, never free text, so a
/// credential naming any other id is [`CredentialRejection::Malformed`],
/// however well signed.
pub fn is_valid_id(id: &str) -> bool {
    (1..=MAX_ID_BYTES).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// [`is_valid_id`], as an argument check for a door that takes an id: an
/// [`Error::InvalidArgument`] naming `what` otherwise.
pub(crate) fn require_valid_id(id: &str, what: &str) -> Result<()> {
    if is_valid_id(id) {
        Ok(())
    } else {
        Err(Error::invalid(format!(
            "{what} must be 1 to {MAX_ID_BYTES} bytes of ASCII letters, digits, '.', '_' or '-'"
        )))
    }
}

/// A raw Ed25519 public key, server or device.
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;

/// A raw Ed25519 signature.
pub const ED25519_SIGNATURE_BYTES: usize = 64;

/// The largest token this crate will look at. See the module header — this is
/// a denial-of-service bound sized for post-quantum keys, not a format rule.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// base64url, read with or without padding. What refuses a padded segment
/// is the canonical rebuild in [`DeviceCredential::parse`], not this decoder.
const B64URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Standard base64, for `device_key` and the account fields — the server
/// writes them with `Buffer.toString("base64")`, which pads, and padded is
/// the one spelling [`DeviceCredential::parse`] accepts.
const B64_STD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The credential payload, field for field with `CredentialPayload` in
/// the server's credential issuer.
///
/// Field ORDER matters and is load-bearing: serializing this struct must
/// reproduce the server's `canonicalPayload` byte for byte, or a fixture minted
/// on one side stops verifying on the other. Nothing in the verify path
/// re-serializes — see the module header — but the `issuer` module (behind the
/// `test-issuer` feature) does, and the
/// round-trip test holds the two together.
///
/// `deny_unknown_fields`: a payload with a key this struct does not name is
/// [`CredentialRejection::Malformed`], never a device with the key ignored.
/// See the module header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialPayload {
    /// Format version. Always 1 in this build.
    pub v: u8,
    /// Which server key signed this. First 8 hex of sha256 over the raw public
    /// key; a lookup hint, not a security claim.
    pub kid: String,
    /// The account's actor id — the KEY layer of identity, never shown to a
    /// person (docs/identity.md §Accounts, sessions and devices).
    pub actor_id: String,
    /// `devices.id`.
    pub device_id: String,
    /// Standard base64 of the device's raw 32-byte Ed25519 public key.
    pub device_key: String,
    /// Standard base64 of the ACCOUNT's 32-byte Ed25519 identity key
    /// ([`crate::account_identity`]), or `""` for a device the account has
    /// not let in yet. Written by the server, but not the server's to vouch
    /// for: [`Self::account_sig`] is checked by every reader against this key
    /// and the key against the reader's own pin.
    pub account_key: String,
    /// Standard base64 of the account identity key's 64-byte signature over
    /// `device_key` ([`crate::account_identity::account_device_statement`]),
    /// or `""` exactly when `account_key` is.
    pub account_sig: String,
    /// Unix seconds.
    pub iat: i64,
    /// Unix seconds.
    pub exp: i64,
}

/// A parsed, **not yet verified** credential.
///
/// Parsing is deliberately separate from verifying, and this type is not
/// `Copy`-cheap to mistake for a verified one: the only way to get a
/// [`crate::identity::PeachyIdentity`] is through
/// [`crate::identity::PeachyIdentityProvider`]. A `DeviceCredential` on its own
/// asserts nothing except "these bytes had the right shape".
#[derive(Debug, Clone)]
pub struct DeviceCredential {
    token: Vec<u8>,
    /// The decoded middle segment, exactly as it arrived. The signed bytes.
    signed_bytes: Vec<u8>,
    signature: [u8; ED25519_SIGNATURE_BYTES],
    payload: CredentialPayload,
    device_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    /// The account identity key and its signature over `device_key`, decoded
    /// but NOT verified. `None` for a device no account device has let in.
    account: Option<(
        [u8; ED25519_PUBLIC_KEY_BYTES],
        [u8; ED25519_SIGNATURE_BYTES],
    )>,
}

impl DeviceCredential {
    /// Read a token's shape. No signature check, no clock check.
    pub fn parse(token: &[u8]) -> Result<Self> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(CredentialRejection::Malformed.into());
        }
        let text = std::str::from_utf8(token).map_err(|_| CredentialRejection::Malformed)?;

        let mut parts = text.split('.');
        let (Some(prefix), Some(payload_seg), Some(sig_seg), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(CredentialRejection::Malformed.into());
        };
        // One prefix. Anything else is malformed: there is no reading of it, and in
        // particular it is never read as a person. A `pdc1` over the wrong
        // version is `UnsupportedVersion`, which is what a future format must
        // look like to this build.
        if prefix != TOKEN_PREFIX {
            return Err(CredentialRejection::Malformed.into());
        }

        let signed_bytes = B64URL
            .decode(payload_seg)
            .map_err(|_| CredentialRejection::Malformed)?;
        let signature_bytes = B64URL
            .decode(sig_seg)
            .map_err(|_| CredentialRejection::Malformed)?;
        if signed_bytes.is_empty() || signature_bytes.len() != ED25519_SIGNATURE_BYTES {
            return Err(CredentialRejection::Malformed.into());
        }
        let mut signature = [0u8; ED25519_SIGNATURE_BYTES];
        signature.copy_from_slice(&signature_bytes);

        // The version first, read loosely, so that a future format — which may
        // well carry fields this build has never heard of — is answered as
        // `UnsupportedVersion` rather than as `Malformed`. Only a payload that
        // claims THIS version is then held to this version's exact shape.
        #[derive(Deserialize)]
        struct VersionOnly {
            v: u8,
        }
        let declared: VersionOnly =
            serde_json::from_slice(&signed_bytes).map_err(|_| CredentialRejection::Malformed)?;
        if declared.v != CREDENTIAL_VERSION {
            return Err(CredentialRejection::UnsupportedVersion.into());
        }
        let payload: CredentialPayload =
            serde_json::from_slice(&signed_bytes).map_err(|_| CredentialRejection::Malformed)?;
        // The ids are names for rows, held to one shape ([`is_valid_id`]):
        // the server chooses them, and an id that carries a separator or a
        // marker could stand for something else wherever ids are listed.
        if !is_key_id(&payload.kid)
            || !is_valid_id(&payload.actor_id)
            || !is_valid_id(&payload.device_id)
        {
            return Err(CredentialRejection::Malformed.into());
        }

        let decoded_key = B64_STD
            .decode(payload.device_key.as_bytes())
            .map_err(|_| CredentialRejection::Malformed)?;
        if decoded_key.len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(CredentialRejection::Malformed.into());
        }
        let mut device_key = [0u8; ED25519_PUBLIC_KEY_BYTES];
        device_key.copy_from_slice(&decoded_key);

        // Both or neither: a key with no signature, or a signature with no
        // key, is not a half-approved device but a malformed token.
        let account = match (
            payload.account_key.is_empty(),
            payload.account_sig.is_empty(),
        ) {
            (true, true) => None,
            (false, false) => {
                let key = B64_STD
                    .decode(payload.account_key.as_bytes())
                    .map_err(|_| CredentialRejection::Malformed)?;
                let sig = B64_STD
                    .decode(payload.account_sig.as_bytes())
                    .map_err(|_| CredentialRejection::Malformed)?;
                let key: [u8; ED25519_PUBLIC_KEY_BYTES] =
                    key.try_into().map_err(|_| CredentialRejection::Malformed)?;
                let sig: [u8; ED25519_SIGNATURE_BYTES] =
                    sig.try_into().map_err(|_| CredentialRejection::Malformed)?;
                Some((key, sig))
            }
            _ => return Err(CredentialRejection::Malformed.into()),
        };

        // One spelling (see the module header): the token rebuilt from what
        // was read must be the token that arrived, so its length is a
        // function of its fields and never the issuer's choice.
        let canonical = CredentialPayload {
            device_key: encode_standard(&device_key),
            account_key: account.map_or_else(String::new, |(key, _)| encode_standard(&key)),
            account_sig: account.map_or_else(String::new, |(_, sig)| encode_standard(&sig)),
            ..payload.clone()
        };
        let canonical_bytes =
            serde_json::to_vec(&canonical).map_err(|_| CredentialRejection::Malformed)?;
        let canonical_token = format!(
            "{TOKEN_PREFIX}.{}.{}",
            encode_base64url(&canonical_bytes),
            encode_base64url(&signature)
        );
        if canonical_token.as_bytes() != token {
            return Err(CredentialRejection::Malformed.into());
        }

        Ok(Self {
            token: token.to_vec(),
            signed_bytes,
            signature,
            payload,
            device_key,
            account,
        })
    }

    /// The token as it arrived — what goes in the leaf.
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// The bytes Ed25519 must check. Never re-serialized.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed_bytes
    }

    pub fn signature(&self) -> &[u8; ED25519_SIGNATURE_BYTES] {
        &self.signature
    }

    pub fn payload(&self) -> &CredentialPayload {
        &self.payload
    }

    /// The device's raw Ed25519 public key. A leaf carrying this credential
    /// MUST have exactly these bytes as its signature key.
    pub fn device_key(&self) -> &[u8; ED25519_PUBLIC_KEY_BYTES] {
        &self.device_key
    }

    /// The account identity key and its signature over [`Self::device_key`],
    /// as the token carries them — unverified. `None` for a device no device
    /// of the account has let in.
    pub fn account(
        &self,
    ) -> Option<&(
        [u8; ED25519_PUBLIC_KEY_BYTES],
        [u8; ED25519_SIGNATURE_BYTES],
    )> {
        self.account.as_ref()
    }
}

/// Decode a standard-base64 raw Ed25519 public key, as published by
/// `GET /healthz/device-credential-keys`.
pub(crate) fn decode_public_key(b64: &str) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES]> {
    let raw = B64_STD
        .decode(b64.as_bytes())
        .map_err(|_| Error::invalid("server public key is not base64"))?;
    if raw.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(Error::invalid(format!(
            "server public key must be {ED25519_PUBLIC_KEY_BYTES} bytes, got {}",
            raw.len()
        )));
    }
    let mut key = [0u8; ED25519_PUBLIC_KEY_BYTES];
    key.copy_from_slice(&raw);
    Ok(key)
}

/// Whether `kid` is a key id as the issuer writes one: the first eight hex
/// characters of SHA-256 over its public key, in lowercase.
fn is_key_id(kid: &str) -> bool {
    kid.len() == 8 && kid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Encode raw bytes the way the server's payload does.
pub(crate) fn encode_standard(bytes: &[u8]) -> String {
    B64_STD.encode(bytes)
}

/// Encode raw bytes the way the token's segments do.
pub(crate) fn encode_base64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
