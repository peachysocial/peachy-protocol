// SPDX-License-Identifier: MIT
//! Commitments to a label's values (draft-ietf-keytrans-protocol-05 §11.6).
//!
//! A prefix tree leaf holds a commitment to the value, never the value:
//! `HMAC-SHA256(Kc, CommitmentValue)`, where the opening is 16 bytes the log
//! draws at random for each version and reveals only to someone it shows the
//! value to. This crate draws no randomness (it also runs as wasm in Node
//! for the log and the auditor), so the caller passes the opening in.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::codec::encode;
use crate::error::{Error, Result};
use crate::suite::{Hash, Opening, COMMITMENT_KEY};
use crate::wire::{CommitmentValue, UpdateValue};

/// The commitment to `value` as `label`'s `version`, under `opening`.
pub fn commit(opening: &Opening, label: &[u8], version: u32, value: &UpdateValue) -> Result<Hash> {
    let input = encode(&CommitmentValue {
        opening: *opening,
        label: label.to_vec(),
        version,
        update: value.clone(),
    })?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&COMMITMENT_KEY)
        .map_err(|_| Error::InvalidArgument("commitment key"))?;
    mac.update(&input);
    Ok(mac.finalize().into_bytes().into())
}

/// Checks, in constant time, that `commitment` opens to `value` as
/// `label`'s `version` under `opening`.
pub fn verify(
    commitment: &Hash,
    opening: &Opening,
    label: &[u8],
    version: u32,
    value: &UpdateValue,
) -> Result<()> {
    let expected = commit(opening, label, version, value)?;
    if bool::from(expected.ct_eq(commitment)) {
        Ok(())
    } else {
        Err(Error::ProofMismatch(
            "commitment does not open to the value",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(b: &[u8]) -> UpdateValue {
        UpdateValue { value: b.to_vec() }
    }

    #[test]
    fn commitment_vector() {
        // HMAC-SHA256 with key d821f8790d97709796b4d7903357c3f5 over
        // 0f*16 || 02 6162 || 00000001 || 00000001 cc, computed independently
        // (`openssl dgst -sha256 -mac HMAC -macopt hexkey:...`).
        let c = commit(&[0x0f; 16], b"ab", 1, &value(&[0xcc])).unwrap();
        assert_eq!(
            hex::encode(c),
            "8038e06ddd9936ea574da5a3807977a03fe88bb6e9ba1ea3860728dc9103c67f"
        );
    }

    #[test]
    fn every_input_changes_the_commitment() {
        let base = commit(&[1; 16], b"label", 3, &value(b"v")).unwrap();
        verify(&base, &[1; 16], b"label", 3, &value(b"v")).unwrap();
        for (opening, label, version, v) in [
            ([2u8; 16], &b"label"[..], 3u32, &b"v"[..]),
            ([1; 16], b"lab3l", 3, b"v"),
            ([1; 16], b"label", 4, b"v"),
            ([1; 16], b"label", 3, b"w"),
            ([1; 16], b"label", 3, b""),
        ] {
            assert_ne!(commit(&opening, label, version, &value(v)).unwrap(), base);
            assert_eq!(
                verify(&base, &opening, label, version, &value(v)),
                Err(Error::ProofMismatch(
                    "commitment does not open to the value"
                ))
            );
        }
    }

    #[test]
    fn an_overlong_label_is_refused() {
        assert!(commit(&[0; 16], &[0; 256], 0, &value(b"")).is_err());
    }
}
