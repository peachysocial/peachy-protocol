// SPDX-License-Identifier: MIT
//! X-Wing KEM known-answer test, for the KEM inside ciphersuite 0x004F.
//!
//! Peachy's one ciphersuite, `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`
//! (0x004F), differs from RFC 9420's suite 0x0001 only in its HPKE KEM: X-Wing
//! (ML-KEM-768 combined with X25519), draft-connolly-cfrg-xwing-kem-06. The RFC
//! 9420 corpus has no entry for 0x004F, so `rfc9420_vectors.rs` checks the
//! primitives the two suites share, and this file checks the one they do not.
//!
//! The vectors are the three in Appendix C of draft-06 — the draft the
//! `x-wing` 0.1.0 crate implements — as published in that crate's
//! `tests/test-vectors.json` and copied here verbatim
//! (`tests/vectors/xwing-draft-06.json`; `tests/vectors/README.md` has the
//! provenance). The file is compiled in with `include_str!`, so a copy of this
//! source without it does not build, and its SHA-256 is checked, so an edited
//! copy fails rather than passing against values nobody published.
//!
//! Each vector is checked through the same crates OpenMLS' provider calls:
//!
//! - deterministic key generation and decapsulation through
//!   `hpke-rs-rust-crypto`'s `HpkeCrypto`, which `openmls_rust_crypto` hands
//!   every X-Wing operation to;
//! - deterministic encapsulation through `x-wing`'s own door, since the HPKE
//!   layer only encapsulates with fresh randomness;
//! - and an HPKE seal to the vector's public key, opened with its private key,
//!   through `OpenMlsRustCrypto` under 0x004F's HPKE configuration.

use hpke_rs_crypto::types::KemAlgorithm;
use hpke_rs_crypto::HpkeCrypto;
use hpke_rs_rust_crypto::HpkeRustCrypto;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{Ciphersuite, HpkeConfig, HpkeKemType};
use openmls_traits::OpenMlsProvider;
use peachy_mls_core::PEACHY_CIPHERSUITE;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x_wing::kem::common::array::Array;

const VECTORS: &str = include_str!("vectors/xwing-draft-06.json");
const VECTORS_SHA256: &str = "a8726596f4c7629590f727b1bbeb483f6932292fbf5fd85c9cbb803190014f00";

#[derive(Deserialize)]
struct Vector {
    seed: String,
    eseed: String,
    ss: String,
    sk: String,
    pk: String,
    ct: String,
}

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap_or_else(|err| panic!("vector field is not hex: {err}"))
}

fn vectors() -> Vec<Vector> {
    assert_eq!(
        hex::encode(Sha256::digest(VECTORS.as_bytes())),
        VECTORS_SHA256,
        "tests/vectors/xwing-draft-06.json is not the file tests/vectors/README.md names"
    );
    let all: Vec<Vector> = serde_json::from_str(VECTORS).expect("xwing-draft-06.json parses");
    assert_eq!(all.len(), 3, "draft-06 Appendix C has three vectors");
    all
}

#[test]
fn the_shipped_suite_uses_the_xwing_kem() {
    assert_eq!(
        PEACHY_CIPHERSUITE,
        Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519
    );
    assert_eq!(PEACHY_CIPHERSUITE as u16, 0x004F);
    assert_eq!(
        PEACHY_CIPHERSUITE.hpke_kem_algorithm(),
        HpkeKemType::XWingKemDraft6
    );
    // The HPKE KEM identifier `openmls_rust_crypto` maps X-Wing to, which goes
    // into every HPKE key schedule's suite id: draft-06's 0x647a, not the
    // obsolete 0x004D.
    assert_eq!(KemAlgorithm::XWingDraft06 as u16, 0x647a);
}

#[test]
fn xwing_keygen_encaps_and_decaps_match_draft_06() {
    for (index, vector) in vectors().iter().enumerate() {
        let (pk, sk) =
            HpkeRustCrypto::kem_key_gen_derand(KemAlgorithm::XWingDraft06, &unhex(&vector.seed))
                .unwrap_or_else(|err| panic!("vector {index}: key generation: {err:?}"));
        assert_eq!(sk, unhex(&vector.sk), "vector {index}: private key");
        assert_eq!(pk, unhex(&vector.pk), "vector {index}: public key");

        let ek = x_wing::EncapsulationKey::try_from(&pk[..])
            .unwrap_or_else(|_| panic!("vector {index}: public key does not parse"));
        let eseed = Array::try_from(&unhex(&vector.eseed)[..])
            .unwrap_or_else(|_| panic!("vector {index}: eseed is not 64 bytes"));
        let (ct, ss) = ek.encapsulate_deterministic(&eseed);
        assert_eq!(
            &ct[..],
            &unhex(&vector.ct)[..],
            "vector {index}: ciphertext"
        );
        assert_eq!(
            &ss[..],
            &unhex(&vector.ss)[..],
            "vector {index}: shared secret (encaps)"
        );

        let decapsulated =
            HpkeRustCrypto::kem_decaps(KemAlgorithm::XWingDraft06, &unhex(&vector.ct), &sk)
                .unwrap_or_else(|err| panic!("vector {index}: decapsulation: {err:?}"));
        assert_eq!(
            decapsulated,
            unhex(&vector.ss),
            "vector {index}: shared secret (decaps)"
        );

        // One flipped ciphertext bit must change the secret: X-Wing decapsulation
        // never fails (ML-KEM rejects implicitly), so a wrong secret is the only
        // sign of a wrong ciphertext.
        let mut tampered = unhex(&vector.ct);
        tampered[0] ^= 1;
        let wrong = HpkeRustCrypto::kem_decaps(KemAlgorithm::XWingDraft06, &tampered, &sk)
            .unwrap_or_else(|err| panic!("vector {index}: decapsulation: {err:?}"));
        assert_ne!(
            wrong,
            unhex(&vector.ss),
            "vector {index}: tampered ciphertext"
        );
    }
}

#[test]
fn hpke_under_the_shipped_suite_opens_with_the_vector_keys() {
    let provider = OpenMlsRustCrypto::default();
    let crypto = provider.crypto();
    let config = || {
        HpkeConfig(
            PEACHY_CIPHERSUITE.hpke_kem_algorithm(),
            PEACHY_CIPHERSUITE.hpke_kdf_algorithm(),
            PEACHY_CIPHERSUITE.hpke_aead_algorithm(),
        )
    };
    for (index, vector) in vectors().iter().enumerate() {
        let sealed = crypto
            .hpke_seal(config(), &unhex(&vector.pk), b"info", b"aad", b"plaintext")
            .unwrap_or_else(|err| panic!("vector {index}: seal: {err:?}"));
        assert_eq!(
            sealed.kem_output.as_slice().len(),
            x_wing::CIPHERTEXT_SIZE,
            "vector {index}: the KEM output is an X-Wing ciphertext"
        );
        let opened = crypto
            .hpke_open(config(), &sealed, &unhex(&vector.sk), b"info", b"aad")
            .unwrap_or_else(|err| panic!("vector {index}: open: {err:?}"));
        assert_eq!(opened, b"plaintext", "vector {index}: round trip");

        // Another vector's private key must not open it.
        let other = &vectors()[(index + 1) % 3];
        assert!(
            crypto
                .hpke_open(config(), &sealed, &unhex(&other.sk), b"info", b"aad")
                .is_err(),
            "vector {index}: opened with the wrong key"
        );
    }
}
