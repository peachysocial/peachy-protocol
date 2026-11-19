// SPDX-License-Identifier: MIT
//! ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 §5, suite string 0x03), and the
//! draft's use of it (draft-ietf-keytrans-protocol-05 §11.7): the search key
//! of a label's version is the VRF output over the encoded `VrfInput`,
//! truncated to 32 bytes.
//!
//! Written on curve25519-dalek, against RFC 9381's own test vectors
//! (Appendix B.3). Verification always validates the public key (RFC 9381
//! §5.4.5): a small-order key is refused, so no proof verifies for every
//! input.
//!
//! Proving needs the VRF private key, which only the log holds, so it is
//! compiled only with the `prover` feature (and in this crate's tests).

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::codec::encode;
use crate::error::{Error, Result};
use crate::suite::{VrfOutput, VrfProof, VRF_OUTPUT_LEN};
use crate::wire::VrfInput;

/// RFC 9381 §5.5: `suite_string` for ECVRF-EDWARDS25519-SHA512-TAI.
const SUITE: u8 = 0x03;
/// `cLen`: the challenge's length in bytes.
const CHALLENGE_LEN: usize = 16;

/// The full 64-byte VRF output, `beta`.
pub type Beta = [u8; 64];

/// RFC 8032 decoding with RFC 9381's strictness: refuses non-canonical
/// encodings (y >= p, or x = 0 with the sign bit set), which
/// `CompressedEdwardsY::decompress` would otherwise accept by reducing.
fn decode_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let point = CompressedEdwardsY(*bytes).decompress()?;
    if point.compress().as_bytes() == bytes {
        Some(point)
    } else {
        None
    }
}

/// RFC 9381 §5.4.1.1, ECVRF_encode_to_curve_try_and_increment, with the
/// public key as the salt.
fn encode_to_curve(pk: &[u8; 32], alpha: &[u8]) -> Result<EdwardsPoint> {
    for ctr in 0u8..=255 {
        let digest = Sha512::new()
            .chain_update([SUITE, 0x01])
            .chain_update(pk)
            .chain_update(alpha)
            .chain_update([ctr, 0x00])
            .finalize();
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(digest.get(..32).ok_or(Error::BadVrfProof)?);
        if let Some(point) = decode_point(&candidate) {
            return Ok(point.mul_by_cofactor());
        }
    }
    // Unreachable in practice: each try succeeds with probability about 1/2.
    Err(Error::BadVrfProof)
}

/// RFC 9381 §5.4.3, ECVRF_challenge_generation, over five points.
fn challenge(points: [&EdwardsPoint; 5]) -> [u8; CHALLENGE_LEN] {
    let mut h = Sha512::new().chain_update([SUITE, 0x02]);
    for p in points {
        h.update(p.compress().as_bytes());
    }
    let digest = h.chain_update([0x00]).finalize();
    let mut c = [0u8; CHALLENGE_LEN];
    for (dst, src) in c.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    c
}

/// The challenge as a scalar (little-endian, RFC 9381 §5.5).
fn challenge_scalar(c: &[u8; CHALLENGE_LEN]) -> Scalar {
    let mut wide = [0u8; 32];
    for (dst, src) in wide.iter_mut().zip(c.iter()) {
        *dst = *src;
    }
    Scalar::from_bytes_mod_order(wide)
}

/// RFC 9381 §5.2, ECVRF_proof_to_hash, over a decoded `Gamma`.
fn proof_to_hash(gamma: &EdwardsPoint) -> Beta {
    Sha512::new()
        .chain_update([SUITE, 0x03])
        .chain_update(gamma.mul_by_cofactor().compress().as_bytes())
        .chain_update([0x00])
        .finalize()
        .into()
}

fn truncate(beta: &Beta) -> VrfOutput {
    let mut out = [0u8; VRF_OUTPUT_LEN];
    for (dst, src) in out.iter_mut().zip(beta.iter()) {
        *dst = *src;
    }
    out
}

/// The encoded `VrfInput { label, version }` (§11.7): the VRF's `alpha`.
pub fn vrf_input(label: &[u8], version: u32) -> Result<Vec<u8>> {
    encode(&VrfInput {
        label: label.to_vec(),
        version,
    })
}

/// A VRF public key (`Configuration.vrf_public_key`), validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfPublicKey {
    bytes: [u8; 32],
    point: EdwardsPoint,
}

impl VrfPublicKey {
    /// RFC 9381 §5.4.5, ECVRF_validate_key: a canonical point that is not of
    /// small order.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
        let point = decode_point(&arr).ok_or(Error::InvalidKey)?;
        if point.is_small_order() {
            return Err(Error::InvalidKey);
        }
        Ok(VrfPublicKey { bytes: arr, point })
    }

    /// The key's 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// RFC 9381 §5.3, ECVRF_verify: the full 64-byte output when `proof` is
    /// valid for `alpha` under this key.
    pub fn verify(&self, alpha: &[u8], proof: &[u8]) -> Result<Beta> {
        let proof: &VrfProof = proof.try_into().map_err(|_| Error::BadVrfProof)?;
        let (gamma_bytes, rest) = proof.split_at(32);
        let (c_bytes, s_bytes) = rest.split_at(CHALLENGE_LEN);
        let gamma_arr: [u8; 32] = gamma_bytes.try_into().map_err(|_| Error::BadVrfProof)?;
        let c: [u8; CHALLENGE_LEN] = c_bytes.try_into().map_err(|_| Error::BadVrfProof)?;
        let s_arr: [u8; 32] = s_bytes.try_into().map_err(|_| Error::BadVrfProof)?;

        let gamma = decode_point(&gamma_arr).ok_or(Error::BadVrfProof)?;
        let s: Option<Scalar> = Scalar::from_canonical_bytes(s_arr).into();
        let s = s.ok_or(Error::BadVrfProof)?;
        let c_scalar = challenge_scalar(&c);

        let h = encode_to_curve(&self.bytes, alpha)?;
        // U = s*B - c*Y, V = s*H - c*Gamma.
        let u = EdwardsPoint::vartime_double_scalar_mul_basepoint(&(-c_scalar), &self.point, &s);
        let v = h * s - gamma * c_scalar;
        let expected = challenge([&self.point, &h, &gamma, &u, &v]);
        if subtle::ConstantTimeEq::ct_eq(&expected[..], &c[..]).into() {
            Ok(proof_to_hash(&gamma))
        } else {
            Err(Error::BadVrfProof)
        }
    }

    /// Verifies the proof for one version of a label and returns the 32-byte
    /// search key (§11.7).
    pub fn verify_label(&self, label: &[u8], version: u32, proof: &[u8]) -> Result<VrfOutput> {
        let alpha = vrf_input(label, version)?;
        Ok(truncate(&self.verify(&alpha, proof)?))
    }
}

/// The VRF private key: the log's alone.
#[cfg(any(test, feature = "prover"))]
pub struct VrfSecretKey {
    scalar: Scalar,
    nonce_prefix: [u8; 32],
    public: VrfPublicKey,
}

#[cfg(any(test, feature = "prover"))]
impl VrfSecretKey {
    /// The key whose RFC 8032 seed (`SK` in RFC 9381) is `seed`.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let expanded = Sha512::digest(seed);
        let mut low = [0u8; 32];
        let mut high = [0u8; 32];
        for (i, b) in expanded.iter().enumerate() {
            if let Some(slot) = low.get_mut(i) {
                *slot = *b;
            } else if let Some(slot) = high.get_mut(i - 32) {
                *slot = *b;
            }
        }
        let scalar = Scalar::from_bytes_mod_order(curve25519_dalek::scalar::clamp_integer(low));
        let point = EdwardsPoint::mul_base(&scalar);
        let public = VrfPublicKey::from_bytes(point.compress().as_bytes())?;
        Ok(VrfSecretKey {
            scalar,
            nonce_prefix: high,
            public,
        })
    }

    /// The matching public key.
    pub fn public_key(&self) -> VrfPublicKey {
        self.public
    }

    /// RFC 9381 §5.1, ECVRF_prove, with the RFC 8032 nonce of §5.4.2.2.
    pub fn prove(&self, alpha: &[u8]) -> Result<(VrfProof, Beta)> {
        let h = encode_to_curve(&self.public.bytes, alpha)?;
        let h_bytes = h.compress();
        let gamma = h * self.scalar;
        let k_digest: [u8; 64] = Sha512::new()
            .chain_update(self.nonce_prefix)
            .chain_update(h_bytes.as_bytes())
            .finalize()
            .into();
        let k = Scalar::from_bytes_mod_order_wide(&k_digest);
        let u = EdwardsPoint::mul_base(&k);
        let v = h * k;
        let c = challenge([&self.public.point, &h, &gamma, &u, &v]);
        let s = k + challenge_scalar(&c) * self.scalar;

        let mut pi = [0u8; crate::suite::VRF_PROOF_LEN];
        let gamma_bytes = gamma.compress();
        let parts: [&[u8]; 3] = [gamma_bytes.as_bytes(), &c, s.as_bytes()];
        for (dst, src) in pi.iter_mut().zip(parts.into_iter().flatten()) {
            *dst = *src;
        }
        Ok((pi, proof_to_hash(&gamma)))
    }

    /// The proof and 32-byte search key for one version of a label.
    pub fn prove_label(&self, label: &[u8], version: u32) -> Result<(VrfProof, VrfOutput)> {
        let alpha = vrf_input(label, version)?;
        let (proof, beta) = self.prove(&alpha)?;
        Ok((proof, truncate(&beta)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arr32(h: &str) -> [u8; 32] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    struct Vector {
        sk: &'static str,
        pk: &'static str,
        alpha: &'static str,
        pi: &'static str,
        beta: &'static str,
    }

    // RFC 9381 Appendix B.3, Examples 16, 17 and 18.
    const VECTORS: [Vector; 3] = [
        Vector {
            sk: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            pk: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            alpha: "",
            pi: "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
            beta: "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
        },
        Vector {
            sk: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            pk: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            alpha: "72",
            pi: "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
            beta: "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
        },
        Vector {
            sk: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            pk: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            alpha: "af82",
            pi: "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
            beta: "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
        },
    ];

    #[test]
    fn rfc9381_vectors_prove_and_verify() {
        for v in &VECTORS {
            let sk = VrfSecretKey::from_seed(&arr32(v.sk)).unwrap();
            assert_eq!(hex::encode(sk.public_key().to_bytes()), v.pk);
            let alpha = hex::decode(v.alpha).unwrap();
            let (pi, beta) = sk.prove(&alpha).unwrap();
            assert_eq!(hex::encode(pi), v.pi);
            assert_eq!(hex::encode(beta), v.beta);

            let pk = VrfPublicKey::from_bytes(&hex::decode(v.pk).unwrap()).unwrap();
            let beta = pk.verify(&alpha, &hex::decode(v.pi).unwrap()).unwrap();
            assert_eq!(hex::encode(beta), v.beta);
        }
    }

    #[test]
    fn rfc9381_intermediate_h_matches() {
        // Example 17: try_and_increment succeeds on ctr = 1.
        let h = encode_to_curve(
            &arr32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            &[0x72],
        )
        .unwrap();
        assert_eq!(
            hex::encode(h.compress().as_bytes()),
            "5b659fc3d4e9263fd9a4ed1d022d75eaacc20df5e09f9ea937502396598dc551"
        );
    }

    #[test]
    fn verify_refuses_tampering() {
        let v = &VECTORS[1];
        let pk = VrfPublicKey::from_bytes(&hex::decode(v.pk).unwrap()).unwrap();
        let pi = hex::decode(v.pi).unwrap();
        // Another alpha.
        assert_eq!(pk.verify(&[0x73], &pi), Err(Error::BadVrfProof));
        // Each part flipped.
        for i in [0usize, 31, 32, 47, 48, 79] {
            let mut bad = pi.clone();
            bad[i] ^= 0x01;
            assert!(pk.verify(&[0x72], &bad).is_err(), "byte {i}");
        }
        // Truncated.
        assert_eq!(pk.verify(&[0x72], &pi[..79]), Err(Error::BadVrfProof));
        // Another key.
        let other = VrfPublicKey::from_bytes(&hex::decode(VECTORS[0].pk).unwrap()).unwrap();
        assert_eq!(other.verify(&[0x72], &pi), Err(Error::BadVrfProof));
        // s >= q: replace s with q itself.
        let mut bad = pi.clone();
        bad[48..].copy_from_slice(
            &hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
                .unwrap(),
        );
        assert_eq!(pk.verify(&[0x72], &bad), Err(Error::BadVrfProof));
    }

    #[test]
    fn small_order_and_noncanonical_keys_are_refused() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(VrfPublicKey::from_bytes(&identity), Err(Error::InvalidKey));
        let order8 = arr32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa");
        assert_eq!(VrfPublicKey::from_bytes(&order8), Err(Error::InvalidKey));
        // (0, -1) with the sign bit set: x = 0 must have a clear sign bit.
        let mut neg = arr32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        neg[31] |= 0x80;
        assert_eq!(VrfPublicKey::from_bytes(&neg), Err(Error::InvalidKey));
        assert_eq!(VrfPublicKey::from_bytes(&[1; 31]), Err(Error::InvalidKey));
    }

    #[test]
    fn label_outputs_are_the_truncated_beta_over_vrf_input() {
        let sk = VrfSecretKey::from_seed(&[3; 32]).unwrap();
        let (proof, out) = sk.prove_label(b"a-label", 5).unwrap();
        let alpha = vrf_input(b"a-label", 5).unwrap();
        // label<0..2^8-1> then uint32 version.
        assert_eq!(hex::encode(&alpha), "07612d6c6162656c00000005");
        let (_, beta) = sk.prove(&alpha).unwrap();
        assert_eq!(out[..], beta[..32]);
        assert_eq!(
            sk.public_key().verify_label(b"a-label", 5, &proof).unwrap(),
            out
        );
        assert!(sk.public_key().verify_label(b"a-label", 6, &proof).is_err());
        assert!(vrf_input(&[0; 256], 0).is_err());
    }
}
