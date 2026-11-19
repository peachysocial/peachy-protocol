// SPDX-License-Identifier: MIT
//! The cipher suite: `KT_128_SHA256_Ed25519` (draft-ietf-keytrans-protocol-05
//! §11.1, §17.1), the only one this crate implements.
//!
//! - Hash: SHA-256, `Hash.Nh` = 32.
//! - Signatures: Ed25519 (RFC 8032), verified strictly: small-order and
//!   non-canonical public keys and non-canonical signatures are refused.
//! - VRF: ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) with its 64-byte output
//!   truncated to 32 bytes (`VRF.Nh` = 32, `VRF.Np` = 80), in [`crate::vrf`].
//! - Commitments: HMAC-SHA256 under the fixed key `Kc` over an `Nc` = 16 byte
//!   opening, in [`crate::commitment`].

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::error::{Error, Result};

/// `Hash.Nh`: the length of every hash value.
pub const HASH_LEN: usize = 32;
/// `Nc`: the length of a commitment opening.
pub const OPENING_LEN: usize = 16;
/// `Kc`: the fixed HMAC key of commitments, hex `d821f8790d97709796b4d7903357c3f5`.
pub const COMMITMENT_KEY: [u8; 16] = [
    0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97, 0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5,
];
/// `VRF.Nh`: the VRF output length after truncation.
pub const VRF_OUTPUT_LEN: usize = 32;
/// `VRF.Np`: the VRF proof length.
pub const VRF_PROOF_LEN: usize = 80;
/// An Ed25519 public key's length.
pub const PUBLIC_KEY_LEN: usize = 32;
/// An Ed25519 signature's length.
pub const SIGNATURE_LEN: usize = 64;

/// `opaque HashValue[Hash.Nh]`.
pub type Hash = [u8; HASH_LEN];
/// A commitment opening.
pub type Opening = [u8; OPENING_LEN];
/// A truncated VRF output: the prefix tree's search key.
pub type VrfOutput = [u8; VRF_OUTPUT_LEN];
/// A VRF proof.
pub type VrfProof = [u8; VRF_PROOF_LEN];

/// `uint16 CipherSuite` (§17.1). Decoding refuses `RESERVED` and any value
/// not listed; private-use values are not accepted either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u16)]
pub enum CipherSuite {
    /// `KT_128_SHA256_P256` (0x0001). Encodable so a configuration naming it
    /// decodes, but nothing in this crate computes with it.
    Kt128Sha256P256 = 0x0001,
    /// `KT_128_SHA256_Ed25519` (0x0002): the Peachy profile's suite.
    Kt128Sha256Ed25519 = 0x0002,
}

impl CipherSuite {
    /// Refuses every suite but the one this crate implements.
    pub fn require_supported(self) -> Result<()> {
        match self {
            CipherSuite::Kt128Sha256Ed25519 => Ok(()),
            CipherSuite::Kt128Sha256P256 => Err(Error::InvalidArgument("unsupported cipher suite")),
        }
    }
}

/// SHA-256 over the concatenation of `parts`.
pub fn hash(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// An Ed25519 public key that has already been checked for small order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Parses a 32-byte key, refusing an invalid point or a small-order one
    /// (a key that would let a signature verify for any message).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
        let key = VerifyingKey::from_bytes(&arr).map_err(|_| Error::InvalidKey)?;
        if key.is_weak() {
            return Err(Error::InvalidKey);
        }
        Ok(PublicKey(key))
    }

    /// The key's 32 bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Verifies `signature` over `message` with RFC 8032's strict rules.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let sig = Signature::from_slice(signature).map_err(|_| Error::BadSignature)?;
        self.0
            .verify_strict(message, &sig)
            .map_err(|_| Error::BadSignature)
    }
}

/// An Ed25519 signing key: the log's, or an auditor's. Clients hold none.
pub struct SecretKey(SigningKey);

impl SecretKey {
    /// The key whose RFC 8032 seed is `seed`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SecretKey(SigningKey::from_bytes(seed))
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Signs `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(message).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode, encode};

    #[test]
    fn suite_codepoints() {
        assert_eq!(
            encode(&CipherSuite::Kt128Sha256Ed25519).unwrap(),
            vec![0x00, 0x02]
        );
        assert_eq!(
            decode::<CipherSuite>(&[0x00, 0x01]).unwrap(),
            CipherSuite::Kt128Sha256P256
        );
        assert!(decode::<CipherSuite>(&[0x00, 0x00]).is_err());
        assert!(decode::<CipherSuite>(&[0xf0, 0x00]).is_err());
        assert!(CipherSuite::Kt128Sha256P256.require_supported().is_err());
    }

    #[test]
    fn hash_is_sha256() {
        // FIPS 180-2 "abc".
        assert_eq!(
            hex::encode(hash(&[b"a", b"bc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rfc8032_test_1_signs_and_verifies() {
        // RFC 8032 §7.1 TEST 1: the empty message.
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let sk = SecretKey::from_seed(&seed);
        assert_eq!(
            hex::encode(sk.public_key().to_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = sk.sign(b"");
        assert_eq!(
            hex::encode(sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        sk.public_key().verify(b"", &sig).unwrap();
    }

    #[test]
    fn signature_negative_cases() {
        let sk = SecretKey::from_seed(&[7; 32]);
        let pk = sk.public_key();
        let sig = sk.sign(b"message");
        assert_eq!(pk.verify(b"massage", &sig), Err(Error::BadSignature));
        let mut flipped = sig;
        flipped[0] ^= 1;
        assert_eq!(pk.verify(b"message", &flipped), Err(Error::BadSignature));
        assert_eq!(pk.verify(b"message", &sig[..63]), Err(Error::BadSignature));
        // s + l: the same signature with a non-canonical scalar.
        let l: [u8; 32] =
            hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
                .unwrap()
                .try_into()
                .unwrap();
        let mut malleable = sig;
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(sig[32 + i]) + u16::from(l[i]) + carry;
            malleable[32 + i] = v as u8;
            carry = v >> 8;
        }
        assert_eq!(pk.verify(b"message", &malleable), Err(Error::BadSignature));
        // Another key.
        let other = SecretKey::from_seed(&[8; 32]).public_key();
        assert_eq!(other.verify(b"message", &sig), Err(Error::BadSignature));
    }

    #[test]
    fn small_order_and_malformed_keys_are_refused() {
        // The identity point.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(PublicKey::from_bytes(&identity), Err(Error::InvalidKey));
        // A point of order 8.
        let order8 =
            hex::decode("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")
                .unwrap();
        assert_eq!(PublicKey::from_bytes(&order8), Err(Error::InvalidKey));
        assert_eq!(PublicKey::from_bytes(&[1; 31]), Err(Error::InvalidKey));
    }
}
