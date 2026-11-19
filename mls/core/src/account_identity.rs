// SPDX-License-Identifier: MIT
//! The account identity key: one Ed25519 key per ACCOUNT, and the signature by
//! which it vouches for each of the account's devices.
//!
//! The model is docs/identity.md §The account identity key, and it
//! closes the one hole a server-issued device credential leaves open.
//! A `pdc1` credential says "the server says this key is one of Ada's
//! devices", and a server that wanted to read Ada's conversations could say
//! that about a key of its own. So every device leaf ALSO carries a signature
//! by Ada's account identity key, and a peer refuses a leaf without one
//! ([`crate::identity`], `validate_seated_credential` and
//! `validate_key_package`).
//!
//! ## Where the key comes from
//!
//! It is DERIVED from the account key of the encrypted account store
//! (docs/account-store.md): `seed = HKDF-SHA256(account_key, info =
//! "peachy account identity v1")`, empty salt. The account key already
//! travels to a newly approved device in a box sealed to that device alone
//! ([`crate::account_store::account_key_seal_hybrid`]), so the box now carries
//! the account's private identity key too. There is no second secret to
//! transfer, back up or lose out of step with the first.
//!
//! A person who loses every device keeps the account key only through a PIN
//! restore (docs/account-store.md §Losing every device), and that
//! keeps the identity key, so no peer sees a change. Otherwise they start
//! over with `ClaimSoleDevice`, which also turns the PIN off, under a new
//! account key ([`crate::account_store::generate_account_key`]). The identity
//! key then changes, a peer's pin no longer matches, and that is what a
//! "security code changed" notice is
//! ([`crate::group::Client::observe_account_keys`]).
//!
//! ## What is signed
//!
//! `"peachy-account-device-v1" || 0x00 || device_key`, where `device_key` is
//! the device's raw 32-byte Ed25519 public key, the same key its leaf signs
//! with. Only the key: the actor and device ids are the server's to assign,
//! and the key is the thing a leaf proves possession of.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::account_store::{hkdf32, ACCOUNT_KEY_BYTES};
use crate::credential::{ED25519_PUBLIC_KEY_BYTES, ED25519_SIGNATURE_BYTES};
use crate::error::{Error, Result};

/// The HKDF `info` that turns an account key into the identity key's seed.
pub const ACCOUNT_IDENTITY_DOMAIN: &str = "peachy account identity v1";

/// The domain of an account's signature over one of its device keys.
pub const ACCOUNT_DEVICE_DOMAIN: &str = "peachy-account-device-v1";

/// An account signature is one Ed25519 signature.
pub const ACCOUNT_SIGNATURE_BYTES: usize = ED25519_SIGNATURE_BYTES;

fn identity_signing_key(account_key: &[u8]) -> Result<SigningKey> {
    if account_key.len() != ACCOUNT_KEY_BYTES {
        return Err(Error::invalid(format!(
            "an account_key must be exactly {ACCOUNT_KEY_BYTES} bytes, got {}",
            account_key.len()
        )));
    }
    let seed = hkdf32(account_key, ACCOUNT_IDENTITY_DOMAIN.as_bytes())?;
    Ok(SigningKey::from_bytes(&seed))
}

/// The bytes an account signs to vouch for one device key.
pub fn account_device_statement(device_key: &[u8]) -> Result<Vec<u8>> {
    if device_key.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(Error::invalid(format!(
            "a device_key must be exactly {ED25519_PUBLIC_KEY_BYTES} bytes, got {}",
            device_key.len()
        )));
    }
    let domain = ACCOUNT_DEVICE_DOMAIN.as_bytes();
    let mut statement = Vec::with_capacity(domain.len() + 1 + device_key.len());
    statement.extend_from_slice(domain);
    statement.push(0);
    statement.extend_from_slice(device_key);
    Ok(statement)
}

/// The account's public identity key, derived from its 32-byte account key.
/// What a peer pins, and what `RegisterDevice` publishes as
/// `account_identity_key`.
pub fn account_identity_public_key(account_key: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES]> {
    Ok(identity_signing_key(account_key)?
        .verifying_key()
        .to_bytes())
}

/// Sign [`account_device_statement`] for `device_key` with the identity key
/// derived from `account_key`. Deterministic (RFC 8032), so a golden fixture
/// pins the bytes.
pub fn sign_account_device(
    account_key: &[u8],
    device_key: &[u8],
) -> Result<[u8; ACCOUNT_SIGNATURE_BYTES]> {
    let signing = identity_signing_key(account_key)?;
    let statement = account_device_statement(device_key)?;
    Ok(signing.sign(&statement).to_bytes())
}

/// Whether `signature` is the account identity key `account_public_key`
/// vouching for `device_key`.
///
/// A plain `bool`, for the reason [`crate::device_link::verify_device_approval`]
/// is one: a wrong length, a key that is not a point and a signature that does
/// not check out all mean "this device is not the account's", and a caller
/// able to tell them apart has nothing to gain from it. `verify_strict`, so a
/// small-order key cannot make one signature verify under two accounts.
pub fn verify_account_device(
    account_public_key: &[u8],
    device_key: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(key_bytes) = <[u8; ED25519_PUBLIC_KEY_BYTES]>::try_from(account_public_key) else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(signature_bytes) = <[u8; ACCOUNT_SIGNATURE_BYTES]>::try_from(signature) else {
        return false;
    };
    let Ok(statement) = account_device_statement(device_key) else {
        return false;
    };
    verifying
        .verify_strict(&statement, &Signature::from_bytes(&signature_bytes))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_verifies_under_the_derived_key_and_nothing_else() {
        let account = [7u8; 32];
        let device = crate::identity::signing_key_public_key(&[9u8; 32]).unwrap_or([0; 32]);
        let public = account_identity_public_key(&account).unwrap_or([0; 32]);
        let signature = sign_account_device(&account, &device).unwrap_or([0; 64]);
        assert!(verify_account_device(&public, &device, &signature));

        let other = account_identity_public_key(&[8u8; 32]).unwrap_or([0; 32]);
        assert!(!verify_account_device(&other, &device, &signature));
        let mut wrong_device = device;
        wrong_device[0] ^= 1;
        assert!(!verify_account_device(&public, &wrong_device, &signature));
        assert!(!verify_account_device(&public, &device, &signature[..63]));
    }

    #[test]
    fn the_wrong_lengths_are_refused() {
        assert!(account_identity_public_key(&[1u8; 31]).is_err());
        assert!(sign_account_device(&[1u8; 32], &[2u8; 31]).is_err());
    }
}
