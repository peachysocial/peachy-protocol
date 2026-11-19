// SPDX-License-Identifier: MIT
//! RFC 9420 interop vectors, from the working group's own corpus.
//!
//! ## What this is, and what it is not
//!
//! OpenMLS runs the full MLS test-vector suite in its own CI. Copying that
//! wholesale into this repo would be megabytes of somebody else's test data
//! proving something OpenMLS already proves. What it would NOT prove is the
//! thing Peachy actually has exposure to: **`openmls_rust_crypto` was explicitly out of scope of the
//! SRLabs audit** and is the provider Peachy ships
//! on every client. So this file runs the vectors that exercise the
//! primitives, against that provider.
//!
//! The corpus has no entry for the one ciphersuite Peachy ships, 0x004F
//! (`MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`). It does have 0x0001,
//! which shares 0x004F's hash, KDF, AEAD and signature scheme and differs only
//! in its HPKE KEM (DHKEM-X25519 where 0x004F has X-Wing). So `crypto-basics`
//! runs for 0x0001: its RefHash, ExpandWithLabel, DeriveSecret,
//! DeriveTreeSecret and SignWithLabel cases cover the same algorithms 0x004F
//! uses, and its EncryptWithLabel case covers HPKE with a KEM 0x004F does not
//! use. The X-Wing KEM itself is checked against its draft's own vectors in
//! `tests/xwing_vectors.rs`.
//!
//! Two suites, and they are honestly different in strength:
//!
//! - **`crypto-basics`** goes through `OpenMlsCrypto` — the trait
//!   `openmls_rust_crypto` implements and the only door OpenMLS itself uses
//!   for hashing, HKDF, signing and HPKE. A regression in that crate, or a
//!   dependency of it, fails here. This is a real conformance check.
//! - **`tree-math`** is checked against a reference implementation written in
//!   this file from RFC 9420 §4.1.2/§4.2. OpenMLS keeps its `treemath` module
//!   crate-private, so it genuinely cannot be reached from a downstream crate.
//!   What this half buys is that the vector corpus is intact and that *our*
//!   reading of the tree numbering is right — which matters, because the C ABI
//!   and every client above it will be passing leaf indices around, and a
//!   sibling/parent confusion there is a bug that looks like a protocol error.
//!   It does not vouch for OpenMLS' tree math. Said plainly here rather than
//!   left for a reader to assume.
//!
//! ## Provenance
//!
//! `tests/vectors/crypto-basics.json` and `tests/vectors/tree-math.json` are
//! the files of `mlswg/mls-implementations` at
//! commit `cfd4502`; `tests/vectors/README.md` carries the URLs, the SHA-256
//! of each file and the commands that fetch them. Both files together are
//! about 110 KB; the large corpora (`treekem.json`, `messages.json`, and the
//! three passive-client sets) are deliberately not used.
//!
//! Upstream states no license for them, so a copy of this source may come
//! without them (the public release does not ship them). Each test then SKIPS:
//! it writes why, and how to fetch the files, to stderr and returns. A file
//! that is present must match its pinned SHA-256, so a wrong or edited copy
//! fails rather than passing against values nobody published.

use std::io::Write as _;
use std::path::PathBuf;

use openmls::prelude::Ciphersuite;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{HashType, HpkeCiphertext, HpkeConfig};
use openmls_traits::OpenMlsProvider;
use peachy_mls_core::PEACHY_CIPHERSUITE;
use serde::Deserialize;
use tls_codec::{Serialize as _, VLBytes};

/// The RFC 9420 suite whose `crypto-basics` entry these tests run: 0x0001,
/// the one that shares every primitive but the KEM with 0x004F, the suite
/// Peachy ships (see the header). The corpus carries seven suites and no
/// 0x004F; the other six use curves and hashes this product never reaches.
const CHECKED_SUITE: u16 = 0x0001;

/// The `mlswg/mls-implementations` commit the vectors are pinned to.
const UPSTREAM_COMMIT: &str = "cfd450286d1bfd9cd2519b95c80f9771f94a5b1a";

/// One vector file under `tests/vectors/`, and the SHA-256 it must have.
struct VectorFile {
    name: &'static str,
    sha256: &'static str,
}

const CRYPTO_BASICS: VectorFile = VectorFile {
    name: "crypto-basics.json",
    sha256: "17cfcf89af9f51d0f2aa7af77f6f9ec99376a039214b6d42a6f11646b83e8c29",
};
const TREE_MATH: VectorFile = VectorFile {
    name: "tree-math.json",
    sha256: "27f04891f56106593b74b674445f01b845e173953770c084deb2f8cf5592e2fc",
};

fn vector_path(file: &VectorFile) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(file.name)
}

/// The file's text, checked against its pinned SHA-256. `None` when the file
/// is absent, after saying so on stderr: the caller returns, and the test is a
/// skip that says it is one.
fn load(file: &VectorFile, test: &str) -> Option<String> {
    let path = vector_path(file);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // Straight to the process's stderr, not `eprintln!`: the test
            // harness swallows a passing test's `eprintln!`, and a skip that
            // nobody sees reads as a pass.
            let _ = writeln!(
                std::io::stderr(),
                "\nSKIPPED {test}: {} is not here.\n  \
                 The RFC 9420 vectors are not distributed with this source (upstream states no license for them).\n  \
                 Fetch them from mlswg/mls-implementations at commit {UPSTREAM_COMMIT}\n  \
                 with the commands in mls/core/tests/vectors/README.md, then run this test again.\n",
                path.display(),
            );
            return None;
        }
        Err(err) => panic!("{}: {err}", path.display()),
    };
    let provider = OpenMlsRustCrypto::default();
    let digest = provider
        .crypto()
        .hash(HashType::Sha2_256, &bytes)
        .unwrap_or_else(|err| panic!("hash: {err}"));
    assert_eq!(
        hex::encode(digest),
        file.sha256,
        "{} is not the file at mlswg/mls-implementations commit {UPSTREAM_COMMIT}; \
         re-fetch it with the commands in tests/vectors/README.md",
        path.display(),
    );
    Some(String::from_utf8(bytes).unwrap_or_else(|err| panic!("{}: {err}", path.display())))
}

// ---- crypto-basics ---------------------------------------------------------

#[derive(Deserialize)]
struct CryptoBasics {
    cipher_suite: u16,
    ref_hash: RefHash,
    expand_with_label: ExpandWithLabel,
    derive_secret: DeriveSecret,
    derive_tree_secret: DeriveTreeSecret,
    sign_with_label: SignWithLabel,
    encrypt_with_label: EncryptWithLabel,
}

#[derive(Deserialize)]
struct RefHash {
    label: String,
    value: String,
    out: String,
}

#[derive(Deserialize)]
struct ExpandWithLabel {
    secret: String,
    label: String,
    context: String,
    length: u16,
    out: String,
}

#[derive(Deserialize)]
struct DeriveSecret {
    secret: String,
    label: String,
    out: String,
}

#[derive(Deserialize)]
struct DeriveTreeSecret {
    secret: String,
    label: String,
    generation: u32,
    length: u16,
    out: String,
}

#[derive(Deserialize)]
struct SignWithLabel {
    #[serde(rename = "pub")]
    public_key: String,
    label: String,
    content: String,
    signature: String,
}

#[derive(Deserialize)]
struct EncryptWithLabel {
    #[serde(rename = "priv")]
    private_key: String,
    label: String,
    context: String,
    plaintext: String,
    kem_output: String,
    ciphertext: String,
}

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap_or_else(|err| panic!("vector field is not hex: {err}"))
}

/// TLS `opaque x<V>`: the variable-length vector encoding MLS uses everywhere.
/// Through `tls_codec` rather than hand-rolled, so the test and the library
/// agree on the length prefix by construction.
fn vlbytes(bytes: &[u8]) -> Vec<u8> {
    VLBytes::from(bytes.to_vec())
        .tls_serialize_detached()
        .unwrap_or_else(|err| panic!("a variable-length vector should encode: {err}"))
}

/// RFC 9420 §5.2: `RefHashInput = struct { opaque label<V>; opaque value<V>; }`.
fn ref_hash(crypto: &impl OpenMlsCrypto, suite: Ciphersuite, label: &str, value: &[u8]) -> Vec<u8> {
    let mut input = vlbytes(label.as_bytes());
    input.extend_from_slice(&vlbytes(value));
    crypto
        .hash(suite.hash_algorithm(), &input)
        .unwrap_or_else(|err| panic!("hash: {err}"))
}

/// RFC 9420 §8.1: `KDFLabel = struct { uint16 length; opaque label<V> =
/// "MLS 1.0 " + Label; opaque context<V>; }`, fed to `KDF.Expand`.
fn expand_with_label(
    crypto: &impl OpenMlsCrypto,
    suite: Ciphersuite,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: u16,
) -> Vec<u8> {
    let mut info = length.to_be_bytes().to_vec();
    info.extend_from_slice(&vlbytes(format!("MLS 1.0 {label}").as_bytes()));
    info.extend_from_slice(&vlbytes(context));
    crypto
        .hkdf_expand(suite.hash_algorithm(), secret, &info, length as usize)
        .unwrap_or_else(|err| panic!("hkdf_expand: {err}"))
        .as_slice()
        .to_vec()
}

#[test]
fn crypto_basics_vectors_pass_for_the_suite_sharing_our_primitives() {
    let provider = OpenMlsRustCrypto::default();
    let crypto = provider.crypto();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    assert_eq!(suite as u16, CHECKED_SUITE);
    // What makes 0x0001 the right stand-in: every primitive but the KEM is
    // the shipped suite's.
    assert_eq!(suite.hash_algorithm(), PEACHY_CIPHERSUITE.hash_algorithm());
    assert_eq!(
        suite.hpke_kdf_algorithm(),
        PEACHY_CIPHERSUITE.hpke_kdf_algorithm()
    );
    assert_eq!(
        suite.hpke_aead_algorithm(),
        PEACHY_CIPHERSUITE.hpke_aead_algorithm()
    );
    assert_eq!(suite.aead_algorithm(), PEACHY_CIPHERSUITE.aead_algorithm());
    assert_eq!(
        suite.signature_algorithm(),
        PEACHY_CIPHERSUITE.signature_algorithm()
    );
    assert_ne!(
        suite.hpke_kem_algorithm(),
        PEACHY_CIPHERSUITE.hpke_kem_algorithm()
    );

    let Some(text) = load(
        &CRYPTO_BASICS,
        "crypto_basics_vectors_pass_for_the_suite_sharing_our_primitives",
    ) else {
        return;
    };
    let all: Vec<CryptoBasics> = serde_json::from_str(&text).expect("crypto-basics.json parses");
    let cases: Vec<&CryptoBasics> = all
        .iter()
        .filter(|case| case.cipher_suite == CHECKED_SUITE)
        .collect();
    assert_eq!(
        cases.len(),
        1,
        "the corpus should carry exactly one entry for ciphersuite 1"
    );

    for case in cases {
        // RefHash — the construction behind every KeyPackageRef and
        // ProposalRef, i.e. the names members use for each other's proposals.
        assert_eq!(
            ref_hash(
                crypto,
                suite,
                &case.ref_hash.label,
                &unhex(&case.ref_hash.value)
            ),
            unhex(&case.ref_hash.out),
            "RefHash"
        );

        // ExpandWithLabel — the root of the whole key schedule.
        assert_eq!(
            expand_with_label(
                crypto,
                suite,
                &unhex(&case.expand_with_label.secret),
                &case.expand_with_label.label,
                &unhex(&case.expand_with_label.context),
                case.expand_with_label.length,
            ),
            unhex(&case.expand_with_label.out),
            "ExpandWithLabel"
        );

        // DeriveSecret = ExpandWithLabel(secret, label, "", KDF.Nh).
        let hash_length = crypto
            .hash(suite.hash_algorithm(), b"")
            .unwrap_or_else(|err| panic!("hash: {err}"))
            .len() as u16;
        assert_eq!(
            expand_with_label(
                crypto,
                suite,
                &unhex(&case.derive_secret.secret),
                &case.derive_secret.label,
                b"",
                hash_length,
            ),
            unhex(&case.derive_secret.out),
            "DeriveSecret"
        );

        // DeriveTreeSecret = ExpandWithLabel(secret, label, generation, length),
        // the per-generation ratchet behind message keys.
        assert_eq!(
            expand_with_label(
                crypto,
                suite,
                &unhex(&case.derive_tree_secret.secret),
                &case.derive_tree_secret.label,
                &case.derive_tree_secret.generation.to_be_bytes(),
                case.derive_tree_secret.length,
            ),
            unhex(&case.derive_tree_secret.out),
            "DeriveTreeSecret"
        );

        // SignWithLabel, verify direction. Signing is randomised for some
        // schemes and deterministic for Ed25519, but the vector only promises
        // that this signature verifies — so that is what is checked, which is
        // also the direction every leaf validation actually runs in.
        let mut sign_content =
            vlbytes(format!("MLS 1.0 {}", case.sign_with_label.label).as_bytes());
        sign_content.extend_from_slice(&vlbytes(&unhex(&case.sign_with_label.content)));
        crypto
            .verify_signature(
                suite.signature_algorithm(),
                &sign_content,
                &unhex(&case.sign_with_label.public_key),
                &unhex(&case.sign_with_label.signature),
            )
            .expect("SignWithLabel: the vector's signature must verify");

        // A signature over the bare content, without the label framing, must
        // NOT verify. Without this the check above would pass for an
        // implementation that ignored the label entirely — and the label is
        // the domain separation.
        assert!(
            crypto
                .verify_signature(
                    suite.signature_algorithm(),
                    &unhex(&case.sign_with_label.content),
                    &unhex(&case.sign_with_label.public_key),
                    &unhex(&case.sign_with_label.signature),
                )
                .is_err(),
            "SignWithLabel: the label framing must be load-bearing"
        );

        // EncryptWithLabel, open direction. Sealing picks an ephemeral key, so
        // it cannot reproduce the vector's bytes; opening them is the
        // deterministic half and is what a Welcome recipient does.
        let mut encrypt_context =
            vlbytes(format!("MLS 1.0 {}", case.encrypt_with_label.label).as_bytes());
        encrypt_context.extend_from_slice(&vlbytes(&unhex(&case.encrypt_with_label.context)));
        let opened = crypto
            .hpke_open(
                HpkeConfig(
                    suite.hpke_kem_algorithm(),
                    suite.hpke_kdf_algorithm(),
                    suite.hpke_aead_algorithm(),
                ),
                &HpkeCiphertext {
                    kem_output: unhex(&case.encrypt_with_label.kem_output).into(),
                    ciphertext: unhex(&case.encrypt_with_label.ciphertext).into(),
                },
                &unhex(&case.encrypt_with_label.private_key),
                &encrypt_context,
                b"",
            )
            .expect("EncryptWithLabel: the vector's ciphertext must open");
        assert_eq!(
            opened,
            unhex(&case.encrypt_with_label.plaintext),
            "EncryptWithLabel"
        );
    }
}

// ---- tree-math -------------------------------------------------------------

#[derive(Deserialize)]
struct TreeMath {
    n_leaves: u32,
    n_nodes: u32,
    root: u32,
    left: Vec<Option<u32>>,
    right: Vec<Option<u32>>,
    parent: Vec<Option<u32>>,
    sibling: Vec<Option<u32>>,
}

/// RFC 9420 §4.1.2. `x` is a NODE index in the array representation: leaves are
/// even, parents odd, and a node's level is its count of trailing one bits.
mod treemath {
    pub fn log2(x: u32) -> u32 {
        if x == 0 {
            return 0;
        }
        let mut k = 0;
        while (x >> k) > 0 {
            k += 1;
        }
        k - 1
    }

    pub fn level(x: u32) -> u32 {
        if x & 1 == 0 {
            return 0;
        }
        let mut k = 0;
        while (x >> k) & 1 == 1 {
            k += 1;
        }
        k
    }

    pub fn node_width(leaves: u32) -> u32 {
        if leaves == 0 {
            0
        } else {
            2 * leaves - 1
        }
    }

    pub fn root(leaves: u32) -> u32 {
        (1 << log2(node_width(leaves))) - 1
    }

    pub fn left(x: u32) -> Option<u32> {
        let k = level(x);
        if k == 0 {
            // A leaf has no children. RFC 9420 calls this an error; the
            // vectors spell it `null`.
            return None;
        }
        Some(x ^ (1 << (k - 1)))
    }

    pub fn right(x: u32) -> Option<u32> {
        let k = level(x);
        if k == 0 {
            return None;
        }
        Some(x ^ (3 << (k - 1)))
    }

    pub fn parent(x: u32, leaves: u32) -> Option<u32> {
        if x == root(leaves) {
            return None;
        }
        let k = level(x);
        let b = (x >> (k + 1)) & 1;
        Some((x | (1 << k)) ^ (b << (k + 1)))
    }

    pub fn sibling(x: u32, leaves: u32) -> Option<u32> {
        let p = parent(x, leaves)?;
        if x < p {
            right(p)
        } else {
            left(p)
        }
    }
}

#[test]
fn tree_math_vectors_match_the_rfc_numbering() {
    let Some(text) = load(&TREE_MATH, "tree_math_vectors_match_the_rfc_numbering") else {
        return;
    };
    let all: Vec<TreeMath> = serde_json::from_str(&text).expect("tree-math.json parses");
    assert!(
        all.len() >= 10,
        "the corpus should carry the powers-of-two trees"
    );

    for case in &all {
        assert_eq!(
            treemath::node_width(case.n_leaves),
            case.n_nodes,
            "node_width({})",
            case.n_leaves
        );
        assert_eq!(
            treemath::root(case.n_leaves),
            case.root,
            "root({})",
            case.n_leaves
        );

        for (arrays, name) in [
            (&case.left, "left"),
            (&case.right, "right"),
            (&case.parent, "parent"),
            (&case.sibling, "sibling"),
        ] {
            assert_eq!(
                arrays.len() as u32,
                case.n_nodes,
                "{name} array length for {} leaves",
                case.n_leaves
            );
        }

        for x in 0..case.n_nodes {
            let i = x as usize;
            assert_eq!(
                treemath::left(x),
                case.left[i],
                "left({x}) in a tree of {} leaves",
                case.n_leaves
            );
            assert_eq!(
                treemath::right(x),
                case.right[i],
                "right({x}) in a tree of {} leaves",
                case.n_leaves
            );
            assert_eq!(
                treemath::parent(x, case.n_leaves),
                case.parent[i],
                "parent({x}) in a tree of {} leaves",
                case.n_leaves
            );
            assert_eq!(
                treemath::sibling(x, case.n_leaves),
                case.sibling[i],
                "sibling({x}) in a tree of {} leaves",
                case.n_leaves
            );
        }
    }
}
