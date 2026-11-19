// SPDX-License-Identifier: MIT
//! The golden account-store fixture: its GENERATOR, and its Rust replay.
//!
//! `mls/fixtures/account-store.json` is a table of (inputs, expected verdict)
//! over `mls/core/src/account_store.rs`: the key a record is sealed under,
//! what a sealed record opens to, what an account-key box opens to, when a
//! new device accepts one, and every refusal a wrong input must meet. This file is the Rust half of its replay;
//! `mls/wasm/tests/node/account-store.test.mjs`,
//! `mls/swift/Tests/PeachyMLSTests/AccountStoreFixtureTests.swift` and
//! the Android binding's `AccountStoreFixtureTest` (not in this repository) are the
//! other three, through each binding's door.
//!
//! ## Why this file also WRITES the fixture
//!
//! Sealing is randomised — a fresh nonce per record, a fresh ephemeral per box
//! — so a sealed value cannot be typed out by hand the way a device-link
//! statement can. The values in the table are made by the Rust-only
//! `store_seal_with` / `account_key_seal_with`, from fixed nonces and fixed
//! ephemerals written below, and `the_committed_fixture_is_what_the_generator_writes`
//! holds the committed file to exactly that output. Regenerate after an
//! intended change with:
//!
//! ```text
//! cd mls && PEACHY_WRITE_ACCOUNT_STORE_FIXTURE=1 cargo test -p peachy-mls-core \
//!     --all-features --test account_store_fixture
//! ```
//!
//! The EXPECTED side of every open case is the input the generator sealed —
//! the plaintext it chose, the account key it boxed — never the output of an
//! open, so the table cannot round-trip its own mistake. The record-key cases
//! are the one derived expectation, and they were checked once against an
//! independent HKDF (Node's `crypto.hkdfSync`) when the table was first made.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::vec_init_then_push)]

use std::collections::BTreeSet;

use peachy_mls_core::account_store::{
    account_key_accept_hybrid, account_key_open, account_key_seal, account_key_seal_linked,
    account_key_seal_linked_with, account_key_seal_with, generate_account_key, note_key,
    note_open_signed, note_seal_signed, note_seal_signed_with, note_seal_with, note_sender,
    record_key, store_open, store_seal, store_seal_with, transfer_key_open, transfer_key_seal,
    transfer_key_seal_with, ACCOUNT_KEY_BOX_DOMAIN, ACCOUNT_KEY_BOX_HYBRID_BYTES,
    ACCOUNT_KEY_BOX_LINKED_DOMAIN, MANIFEST_ID, NOTE_KEY_DOMAIN, NOTE_MAX_AGE_MS,
    NOTE_MAX_AHEAD_MS, NOTE_SIGNATURE_DOMAIN, NOTE_SIGNED_KEY_DOMAIN, STORE_RECORD_KEY_DOMAIN,
    TRANSFER_KEY_DOMAIN,
};
use peachy_mls_core::fixture::{evaluate_case_json, FORMAT_VERSION};
use peachy_mls_core::signing_key_public_key;
use serde::Serialize;
use serde_json::Value;

const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fixtures/account-store.json"
);
const FIXTURE: &str = include_str!("../../fixtures/account-store.json");

/// Every `call` the table has to reach.
const CALLS: [&str; 8] = [
    "recordKey",
    "storeOpen",
    "boxOpen",
    "boxAccept",
    "boxAcceptHybrid",
    "noteSender",
    "noteOpenSigned",
    "transferKeyOpen",
];

// ---- The generator's inputs: repeated bytes, never real key material --------

const ACCOUNT_KEY: [u8; 32] = [0xa1; 32];
const OTHER_ACCOUNT_KEY: [u8; 32] = [0xa2; 32];
const CONTACT_ID: [u8; 16] = [0x11; 16];
const CHAT_ID: [u8; 16] = [0x22; 16];
/// A self-note's id.
const NOTE_ID: [u8; 16] = [0x99; 16];
/// Ada's phone, the APPROVING device — the same seed device-link.json uses.
const APPROVER_SEED: [u8; 32] = [0x11; 32];
/// A device that did not approve anything.
const WRONG_APPROVER_SEED: [u8; 32] = [0x44; 32];
/// A seed that is nobody's device: what a server could make up.
const FORGER_SEED: [u8; 32] = [0x77; 32];
/// The new laptop, the RECIPIENT.
const RECIPIENT_SEED: [u8; 32] = [0x33; 32];
/// Some other device that is not the recipient.
const BYSTANDER_SEED: [u8; 32] = [0x55; 32];
const DEVICE_ID: &str = "0f8e2b1c-6a4d-4e3f-9b2a-7c5d1e0f3a9b";
const EPHEMERAL: [u8; 32] = [0x5e; 32];
const BOX_NONCE: [u8; 12] = [0x66; 12];
/// The key of a history hand-off's document, sealed to the laptop.
const TRANSFER_KEY: [u8; 32] = [0x7c; 32];
/// A link secret, for the inner opener's version-2 cases; no client sends one.
const QR_LINK_KEY: [u8; 32] = [0x5f; 32];
/// A link secret nobody showed: what a server would have to guess.
const WRONG_QR_LINK_KEY: [u8; 32] = [0x60; 32];
/// The seed of the X-Wing link key the new laptop posted with its nonce.
const LINK_KEY_SEED: [u8; 32] = [0x5a; 32];
/// A link key seed the laptop never drew.
const WRONG_LINK_KEY_SEED: [u8; 32] = [0x5b; 32];
/// Ada's phone (1111..) sealing ACCOUNT_KEY to the laptop (3333..) for
/// DEVICE_ID under the link key LINK_KEY_SEED derives: a version-3 box.
///
/// The one sealed value the generator does not make itself. The X-Wing
/// encapsulation draws its randomness inside the HPKE library, which takes no
/// fixed coins, so this box was sealed once by `account_key_seal_hybrid` and
/// written down. The expected side of its cases is still the account key the
/// generator chose, never an open's output.
const HYBRID_BOX_HEX: &str = "03213c2c9b7e91703d94d02664f399c167991b4c4428d6b09b799a9807f122b33480cb435561eb2c0787a5180572070fe377da342db45f8e20e041985086f46e182fc3f2f39e9ad7c80e81b57bf6d1265b1dcf5dd5ff01ae498596d15c31840640024774f4ce3c08c5eb8614b89a209bc91185552c3b3fd8e1b7f115b1f22abc83d13ffa90c0f6a94f1a0dfa224b1de0a117d6da23e67c368b925ce3cfd7e900a04925394e1b69c193786c5ec6de1831903c7da621fdc52c9cda0851ed45de57aadf296151f6de2178c6fe97768a5b1fd8eb5d2f11bbbcf4260fe232f2d4c4c8a5a0770f614ef343104b1c4ae96e3289b84a57ebb8c7f2f7092b2378be27b64cd20150a091d5e86a9ce70e5959a442f47479529177f2929ad933396029530fba50276b0ea89b6d53741de69fccef35012f966d30223cd031a4ef736c8601929c8f99ead25508f83a2a52c967157b2c795735a8f96752e556de3bea0f1fe21affce3516416a8c6d5240a577994c68c05c7ee44ee4c9e30ec36c698d6a993a914fd0d94798bfa3a065070976af65aedfaf64cc6240e69cee14dae8067f438e6616c81c3b253f4b7415188f755e27952167142874499f6b17946ec3314092e646388667f89eaaa92a9e24dd192166960e209886fc1277282aba86257b9f8dc6737be2cd71e0671d540047bc4b231f43154780b9249472c6f75b2fcf8de295f97592fa8b74403175d5205406a301300622b08be43a1c1b3cff62286fe9c82e2377606d4c298e5f30c0759fb8a9091c9c10d6aca9d1dc8395d6587757ef0d96bb9eafff547849bbf5058da04e6a40f278be93381bd6f8dc737ebfc450f76bc0639be7fffd7bc6d6dc71e982496cbdeafe9b0f17d1a67cb0692cb587d17cf59ff93b3eb45dfe7486b6b5f7404c1ef1edb46f55b2b03241324b5e9582a95a34a0bcce016f6e469a77d9f762754805eb3007afed192cc9adff3b41065d4c5ce4ece697c0fe19f4b4c90a79d4a143eb58a43150168b0f8b032ad53949855056cdb6f866a500fa2227be643785f8733c873e38e7f587414506e11c116247bfddac12122ed7b914c56be2088a587a4ab90d0ec21503dd8b5a3b0a0eadbcbfb358d79e26db77f6622db40507df35c62740b7cda7a8fd65593f467601901b0bc10c3d4176e17a81fa435e200f17a5d0ee51c237f1f6176cf05874d8c3ec5dd5f09881779c647214d5dca53ad312afe62901e825337bdb0df77fc1e2d84c0024637e9e2622b104ee7a6fc1280fea3e8fb5316ffda2078f188a26bc43581f5377bc2299df647b070f57eae0f0f16530a51e399f5b8e67caf61f3c3bd6a740cf54177d1d06cf3e98270601e25b1f1cc51627f5929e8f14c8538fd7da8e6e55c0d971e6260647efe3d328786184a78dee15fa0046be351ce57436fb635c4d4d1cd8e0945ffdc42ae09fddcc840d407f90428342bc6a6d0937cbc4675470921d5c72d007a2835c750f046604c56c44820b642c4a7d37966d9c079fd38ca7c8c4c0db0dfcad8d9a3eb81e5aa0a381a191c3e81824fcbd4a2e0ceb79474ec096d25c6efc1b68fe008e00d84873015e751eed53320b57e7d94eef4cfced11f5566bbaedd4271da472ea6670eb7aad0fcbd7b9ee1d0492db0f36dd877747f1b423b6776f177c050d2225a80358eab29a09650fc1c00e80798d877ab8f6861b310f59db355951f3fe";
/// Ada's phone's `devices.id`, the sender of the signed notes.
const PHONE_DEVICE_ID: &str = "6a1c0e52-2f4b-4c3d-8e9f-0a1b2c3d4e5f";
/// When the signed notes were issued, unix milliseconds.
const NOTE_ISSUED_AT: i64 = 1_790_000_000_000;

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct Case {
    id: String,
    kind: &'static str,
    call: &'static str,
    why: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient_seed_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approver_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    box_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_secret_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmed_approver_key_hex: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    server_approval_allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_key_seed_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    now_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expect: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expect_error: Option<&'static str>,
}

#[derive(Serialize)]
struct Fixture {
    version: u32,
    about: Vec<&'static str>,
    cases: Vec<Case>,
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn public(seed: &[u8; 32]) -> [u8; 32] {
    signing_key_public_key(seed).expect("a public half")
}

fn nonce(n: u8) -> [u8; 12] {
    [n; 12]
}

fn record_key_case(id: &str, why: &str, account_key: &[u8], store_id: &[u8]) -> Case {
    Case {
        id: id.into(),
        kind: "account_store",
        call: "recordKey",
        why: why.into(),
        account_key_hex: Some(hex(account_key)),
        id_hex: Some(hex(store_id)),
        expect: Some(serde_json::json!({
            "keyHex": hex(&record_key(account_key, store_id).expect("a record key"))
        })),
        ..Case::default()
    }
}

fn store_open_case(
    id: &str,
    why: &str,
    account_key: &[u8],
    store_id: &[u8],
    value: &[u8],
    outcome: Result<&[u8], &'static str>,
) -> Case {
    let (expect, expect_error) = match outcome {
        Ok(plaintext) => (
            Some(serde_json::json!({ "plaintextHex": hex(plaintext) })),
            None,
        ),
        Err(message) => (None, Some(message)),
    };
    Case {
        id: id.into(),
        kind: "account_store",
        call: "storeOpen",
        why: why.into(),
        account_key_hex: Some(hex(account_key)),
        id_hex: Some(hex(store_id)),
        value_hex: Some(hex(value)),
        expect,
        expect_error,
        ..Case::default()
    }
}

/// A `noteSender` case: which device a signed note says sent it.
fn note_sender_case(
    id: &str,
    why: &str,
    note_id: &[u8],
    value: &[u8],
    outcome: Result<&str, &'static str>,
) -> Case {
    let (expect, expect_error) = match outcome {
        Ok(sender) => (Some(serde_json::json!({ "senderDeviceId": sender })), None),
        Err(message) => (None, Some(message)),
    };
    Case {
        id: id.into(),
        kind: "account_store",
        call: "noteSender",
        why: why.into(),
        account_key_hex: Some(hex(&ACCOUNT_KEY)),
        id_hex: Some(hex(note_id)),
        value_hex: Some(hex(value)),
        expect,
        expect_error,
        ..Case::default()
    }
}

/// A `noteOpenSigned` case: a signed note, believed for `sender` under
/// `sender_key` at `now_ms`.
#[allow(clippy::too_many_arguments)]
fn note_open_signed_case(
    id: &str,
    why: &str,
    note_id: &[u8],
    value: &[u8],
    sender: &str,
    sender_key: &[u8],
    now_ms: i64,
    outcome: Result<&[u8], &'static str>,
) -> Case {
    Case {
        call: "noteOpenSigned",
        device_id: Some(sender.into()),
        sender_key_hex: Some(hex(sender_key)),
        now_ms: Some(now_ms),
        ..store_open_case(id, why, &ACCOUNT_KEY, note_id, value, outcome)
    }
}

fn box_open_case(
    id: &str,
    why: &str,
    recipient_seed: &[u8],
    approver_key: &[u8],
    device_id: &str,
    sealed_box: &[u8],
    outcome: Result<&[u8], &'static str>,
) -> Case {
    let (expect, expect_error) = match outcome {
        Ok(key) => (Some(serde_json::json!({ "accountKeyHex": hex(key) })), None),
        Err(message) => (None, Some(message)),
    };
    Case {
        id: id.into(),
        kind: "account_store",
        call: "boxOpen",
        why: why.into(),
        recipient_seed_hex: Some(hex(recipient_seed)),
        approver_key_hex: Some(hex(approver_key)),
        device_id: Some(device_id.into()),
        box_hex: Some(hex(sealed_box)),
        expect,
        expect_error,
        ..Case::default()
    }
}

/// What the new device vouched for: a link secret (the inner opener's
/// version-2 cases only), the approver key whose number the person picked on it, and its own switch for
/// server-run approvals.
#[derive(Default, Clone, Copy)]
struct Vouched<'a> {
    link_secret: Option<&'a [u8]>,
    confirmed_approver_key: Option<&'a [u8]>,
    server_approval_allowed: bool,
}

#[allow(clippy::too_many_arguments)]
fn box_accept_case(
    id: &str,
    why: &str,
    recipient_seed: &[u8],
    approver_key: &[u8],
    device_id: &str,
    sealed_box: &[u8],
    vouched: Vouched<'_>,
    outcome: Result<&[u8], &'static str>,
) -> Case {
    Case {
        call: "boxAccept",
        link_secret_hex: vouched.link_secret.map(hex),
        confirmed_approver_key_hex: vouched.confirmed_approver_key.map(hex),
        server_approval_allowed: vouched.server_approval_allowed,
        ..box_open_case(
            id,
            why,
            recipient_seed,
            approver_key,
            device_id,
            sealed_box,
            outcome,
        )
    }
}

/// What the new device holds for the version-3 door: what it vouched for,
/// and the seed of the link key it posted.
#[derive(Default, Clone, Copy)]
struct Hybrid<'a> {
    vouched: Vouched<'a>,
    link_key_seed: Option<&'a [u8]>,
}

fn box_accept_hybrid_case(
    id: &str,
    why: &str,
    approver_key: &[u8],
    sealed_box: &[u8],
    held: Hybrid<'_>,
    outcome: Result<&[u8], &'static str>,
) -> Case {
    Case {
        call: "boxAcceptHybrid",
        link_key_seed_hex: held.link_key_seed.map(hex),
        ..box_accept_case(
            id,
            why,
            &RECIPIENT_SEED,
            approver_key,
            DEVICE_ID,
            sealed_box,
            held.vouched,
            outcome,
        )
    }
}

fn transfer_key_open_case(
    id: &str,
    why: &str,
    recipient_seed: &[u8],
    device_id: &str,
    sealed_box: &[u8],
    outcome: Result<&[u8], &'static str>,
) -> Case {
    let (expect, expect_error) = match outcome {
        Ok(key) => (
            Some(serde_json::json!({ "transferKeyHex": hex(key) })),
            None,
        ),
        Err(message) => (None, Some(message)),
    };
    Case {
        id: id.into(),
        kind: "account_store",
        call: "transferKeyOpen",
        why: why.into(),
        recipient_seed_hex: Some(hex(recipient_seed)),
        device_id: Some(device_id.into()),
        box_hex: Some(hex(sealed_box)),
        expect,
        expect_error,
        ..Case::default()
    }
}

fn unhex_str(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

const DOES_NOT_OPEN: &str = "does not open under this key and id";
const NOT_CONFIRMED: &str = "an approver the person did not confirm on this device";
const BOX_DOES_NOT_OPEN: &str = "does not open for this device, approver and device id";
const TRANSFER_DOES_NOT_OPEN: &str =
    "the transfer key box does not open for this device and device id";

/// The whole table, deterministically.
fn generate() -> String {
    let mut cases = Vec::new();

    // ---- recordKey --------------------------------------------------------
    cases.push(record_key_case(
        "record-key/contact-id",
        "k(id) = HKDF-SHA256(account_key, salt empty, info \"peachy store v1\" 0x00 id).",
        &ACCOUNT_KEY,
        &CONTACT_ID,
    ));
    cases.push(record_key_case(
        "record-key/manifest-id",
        "The manifest's key: the same derivation over the reserved all-zero id.",
        &ACCOUNT_KEY,
        &MANIFEST_ID,
    ));
    cases.push(record_key_case(
        "record-key/other-account",
        "Same id, another account: a different key.",
        &OTHER_ACCOUNT_KEY,
        &CONTACT_ID,
    ));
    cases.push(Case {
        id: "record-key/id-of-15-bytes".into(),
        kind: "account_store",
        call: "recordKey",
        why: "An id is exactly 16 bytes; anything else is a caller's bug, not an id.".into(),
        account_key_hex: Some(hex(&ACCOUNT_KEY)),
        id_hex: Some(hex(&CONTACT_ID[..15])),
        expect_error: Some("a store id must be exactly 16 bytes, got 15"),
        ..Case::default()
    });
    cases.push(Case {
        id: "record-key/account-key-of-31-bytes".into(),
        kind: "account_store",
        call: "recordKey",
        why: "An account key is exactly 32 bytes.".into(),
        account_key_hex: Some(hex(&ACCOUNT_KEY[..31])),
        id_hex: Some(hex(&CONTACT_ID)),
        expect_error: Some("an account_key must be exactly 32 bytes, got 31"),
        ..Case::default()
    });

    // ---- storeOpen: what a value opens to ---------------------------------
    let empty = store_seal_with(&ACCOUNT_KEY, &CONTACT_ID, &[], &nonce(1)).unwrap();
    cases.push(store_open_case(
        "store-open/empty-plaintext",
        "An empty plaintext pads to one whole block: 0x80 then 255 zeros.",
        &ACCOUNT_KEY,
        &CONTACT_ID,
        &empty,
        Ok(&[]),
    ));

    let p255: Vec<u8> = (0..255u32).map(|i| (i % 251) as u8).collect();
    let v255 = store_seal_with(&ACCOUNT_KEY, &CONTACT_ID, &p255, &nonce(2)).unwrap();
    cases.push(store_open_case(
        "store-open/255-bytes",
        "255 bytes plus the 0x80 marker fill exactly one 256-byte block.",
        &ACCOUNT_KEY,
        &CONTACT_ID,
        &v255,
        Ok(&p255),
    ));

    let p256: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
    let v256 = store_seal_with(&ACCOUNT_KEY, &CONTACT_ID, &p256, &nonce(3)).unwrap();
    cases.push(store_open_case(
        "store-open/256-bytes",
        "256 bytes leave no room for the marker, so the padding spills into a second block.",
        &ACCOUNT_KEY,
        &CONTACT_ID,
        &v256,
        Ok(&p256),
    ));

    let p_multi: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 256) as u8).collect();
    let v_multi = store_seal_with(&ACCOUNT_KEY, &CHAT_ID, &p_multi, &nonce(4)).unwrap();
    cases.push(store_open_case(
        "store-open/multi-bucket",
        "1000 bytes pad to 1024: four blocks. Plaintext bytes include 0x00 and 0x80, which unpad must leave alone.",
        &ACCOUNT_KEY,
        &CHAT_ID,
        &v_multi,
        Ok(&p_multi),
    ));

    let contact =
        br#"{"kind":"contact","key":"actor-ada","at":1789516800000,"value":{"name":"Ada"}}"#;
    let v_contact = store_seal_with(&ACCOUNT_KEY, &CONTACT_ID, contact, &nonce(5)).unwrap();
    cases.push(store_open_case(
        "store-open/contact-record",
        "A record in the shape the clients write: UTF-8 JSON.",
        &ACCOUNT_KEY,
        &CONTACT_ID,
        &v_contact,
        Ok(contact),
    ));

    let manifest = format!(
        r#"{{"version":1,"ids":["{}","{}"]}}"#,
        hex(&CONTACT_ID),
        hex(&CHAT_ID)
    );
    let v_manifest =
        store_seal_with(&ACCOUNT_KEY, &MANIFEST_ID, manifest.as_bytes(), &nonce(6)).unwrap();
    cases.push(store_open_case(
        "store-open/manifest",
        "The manifest is sealed exactly like a record, under MANIFEST_ID (16 zero bytes).",
        &ACCOUNT_KEY,
        &MANIFEST_ID,
        &v_manifest,
        Ok(manifest.as_bytes()),
    ));

    // ---- storeOpen: refusals ----------------------------------------------
    cases.push(store_open_case(
        "store-open/wrong-id",
        "The server serves the contact's value under the chat's id. The id is in the key AND the AAD.",
        &ACCOUNT_KEY,
        &CHAT_ID,
        &v_contact,
        Err(DOES_NOT_OPEN),
    ));
    cases.push(store_open_case(
        "store-open/manifest-under-a-record-id",
        "The manifest served as a record: refused, like any other wrong id.",
        &ACCOUNT_KEY,
        &CONTACT_ID,
        &v_manifest,
        Err(DOES_NOT_OPEN),
    ));
    cases.push(store_open_case(
        "store-open/wrong-account-key",
        "Another account's key.",
        &OTHER_ACCOUNT_KEY,
        &CONTACT_ID,
        &v_contact,
        Err(DOES_NOT_OPEN),
    ));
    let mut tampered = v_contact.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    cases.push(store_open_case(
        "store-open/tampered-tag",
        "One bit of the tag flipped.",
        &ACCOUNT_KEY,
        &CONTACT_ID,
        &tampered,
        Err(DOES_NOT_OPEN),
    ));
    let mut tampered = v_contact.clone();
    tampered[20] ^= 0x80;
    cases.push(store_open_case(
        "store-open/tampered-ciphertext",
        "One bit of the ciphertext flipped.",
        &ACCOUNT_KEY,
        &CONTACT_ID,
        &tampered,
        Err(DOES_NOT_OPEN),
    ));
    let mut tampered = v_contact.clone();
    tampered[1] ^= 0x01;
    cases.push(store_open_case(
        "store-open/tampered-nonce",
        "One bit of the nonce flipped.",
        &ACCOUNT_KEY,
        &CONTACT_ID,
        &tampered,
        Err(DOES_NOT_OPEN),
    ));
    let mut bad_version = v_contact.clone();
    bad_version[0] = 0x02;
    cases.push(store_open_case(
        "store-open/bad-version-byte",
        "0x01 is the only format; a value from a future format is refused by name, not misread.",
        &ACCOUNT_KEY,
        &CONTACT_ID,
        &bad_version,
        Err("unknown store format version 0x02"),
    ));
    cases.push(store_open_case(
        "store-open/id-of-15-bytes",
        "A 15-byte id is refused before anything is decrypted.",
        &ACCOUNT_KEY,
        &CONTACT_ID[..15],
        &v_contact,
        Err("a store id must be exactly 16 bytes, got 15"),
    ));
    cases.push(store_open_case(
        "store-open/truncated",
        "Shorter than version + nonce + tag + one padding block (285 bytes).",
        &ACCOUNT_KEY,
        &CONTACT_ID,
        &v_contact[..284],
        Err("a sealed store value is too short: 284 bytes, at least 285"),
    ));

    // ---- boxOpen -----------------------------------------------------------
    let approver = public(&APPROVER_SEED);
    let recipient = public(&RECIPIENT_SEED);
    let sealed = account_key_seal_with(
        &APPROVER_SEED,
        &recipient,
        DEVICE_ID,
        &ACCOUNT_KEY,
        &EPHEMERAL,
        &BOX_NONCE,
    )
    .unwrap();
    assert_eq!(sealed.len(), 93);
    cases.push(box_open_case(
        "box-open/phone-to-laptop",
        "Ada's phone (seed 1111..) boxes the account key for her new laptop (seed 3333..).",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &sealed,
        Ok(&ACCOUNT_KEY),
    ));
    cases.push(box_open_case(
        "box-open/wrong-approver-key",
        "THE case. The server claims a different approver; the static-static half of the agreement does not match, so it does not open.",
        &RECIPIENT_SEED,
        &public(&WRONG_APPROVER_SEED),
        DEVICE_ID,
        &sealed,
        Err(BOX_DOES_NOT_OPEN),
    ));
    let forged = account_key_seal_with(
        &FORGER_SEED,
        &recipient,
        DEVICE_ID,
        &OTHER_ACCOUNT_KEY,
        &EPHEMERAL,
        &BOX_NONCE,
    )
    .unwrap();
    cases.push(box_open_case(
        "box-open/forged-without-the-approvers-secret",
        "A box built from public keys alone plus a made-up static key: it is a well-formed box and it does not open under Ada's phone.",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &forged,
        Err(BOX_DOES_NOT_OPEN),
    ));
    cases.push(box_open_case(
        "box-open/wrong-device-id",
        "The box replayed onto another device row: the row id is in the HKDF info.",
        &RECIPIENT_SEED,
        &approver,
        "0f8e2b1c-6a4d-4e3f-9b2a-7c5d1e0f3a9c",
        &sealed,
        Err(BOX_DOES_NOT_OPEN),
    ));
    cases.push(box_open_case(
        "box-open/wrong-recipient",
        "Opened by a device it was not made for.",
        &BYSTANDER_SEED,
        &approver,
        DEVICE_ID,
        &sealed,
        Err(BOX_DOES_NOT_OPEN),
    ));
    let mut tampered = sealed.clone();
    tampered[1] ^= 0x01;
    cases.push(box_open_case(
        "box-open/tampered-ephemeral",
        "E is the AEAD's associated data as well as half the agreement.",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &tampered,
        Err(BOX_DOES_NOT_OPEN),
    ));
    let mut tampered = sealed.clone();
    tampered[92] ^= 0x01;
    cases.push(box_open_case(
        "box-open/tampered-tag",
        "One bit of the tag flipped.",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &tampered,
        Err(BOX_DOES_NOT_OPEN),
    ));
    let mut bad_version = sealed.clone();
    bad_version[0] = 0x03;
    cases.push(box_open_case(
        "box-open/bad-version-byte",
        "0x01 and 0x02 are the only box formats.",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &bad_version,
        Err("unknown account key box format version 0x03"),
    ));
    cases.push(box_open_case(
        "box-open/truncated",
        "A box is exactly 93 bytes.",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &sealed[..92],
        Err("an account key box must be exactly 93 bytes, got 92"),
    ));
    cases.push(box_open_case(
        "box-open/empty-device-id",
        "A device id is never empty.",
        &RECIPIENT_SEED,
        &approver,
        "",
        &sealed,
        Err("a device_id must not be empty"),
    ));

    // ---- boxAccept: the new device's door -----------------------------------
    let linked = account_key_seal_linked_with(
        &APPROVER_SEED,
        &recipient,
        DEVICE_ID,
        &ACCOUNT_KEY,
        &QR_LINK_KEY,
        &EPHEMERAL,
        &BOX_NONCE,
    )
    .unwrap();
    assert_eq!(linked.len(), 93);
    assert_eq!(linked[0], 0x02);
    let scanned = Vouched {
        link_secret: Some(&QR_LINK_KEY),
        ..Vouched::default()
    };
    cases.push(box_accept_case(
        "box-accept/scanned-the-qr-code",
        "Ada's phone scanned the laptop's QR code and sealed with the link secret it carried (5f5f..): a version-2 box, which the laptop opens with the secret it showed.",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &linked,
        scanned,
        Ok(&ACCOUNT_KEY),
    ));
    cases.push(box_open_case(
        "box-open/a-linked-box",
        "The plain opener reads version 1 only: a box keyed with a link secret goes through boxAccept.",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &linked,
        Err("format version 0x02; this call reads 0x01"),
    ));
    let forged_linked = account_key_seal_linked_with(
        &FORGER_SEED,
        &recipient,
        DEVICE_ID,
        &OTHER_ACCOUNT_KEY,
        &WRONG_QR_LINK_KEY,
        &EPHEMERAL,
        &BOX_NONCE,
    )
    .unwrap();
    cases.push(box_accept_case(
        "box-accept/the-server-guessed-a-link-secret",
        "THE case for the QR path. A server runs a device of its own (7777..), lists it as an approver, and seals its own account key with a secret it made up. The laptop opens with the secret it showed, and it does not open.",
        &RECIPIENT_SEED,
        &public(&FORGER_SEED),
        DEVICE_ID,
        &forged_linked,
        scanned,
        Err(BOX_DOES_NOT_OPEN),
    ));
    cases.push(box_accept_case(
        "box-accept/a-linked-box-and-no-qr-code",
        "A version-2 box on a device that showed no QR code has nothing to open it with.",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &linked,
        Vouched {
            server_approval_allowed: true,
            ..Vouched::default()
        },
        Err("this device showed no QR code"),
    ));
    cases.push(box_accept_case(
        "box-accept/a-short-link-secret",
        "A link secret is exactly 32 bytes.",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &linked,
        Vouched {
            link_secret: Some(&QR_LINK_KEY[..31]),
            ..Vouched::default()
        },
        Err("a link_secret must be exactly 32 bytes, got 31"),
    ));
    let forged_plain = account_key_seal_with(
        &FORGER_SEED,
        &recipient,
        DEVICE_ID,
        &OTHER_ACCOUNT_KEY,
        &EPHEMERAL,
        &BOX_NONCE,
    )
    .unwrap();
    cases.push(box_accept_case(
        "box-accept/the-server-ran-the-approver",
        "THE case for the number path. The server's own device (7777..) seals a plain box that opens under its own key; the laptop showed a QR code nobody scanned and confirmed no approver, so it refuses.",
        &RECIPIENT_SEED,
        &public(&FORGER_SEED),
        DEVICE_ID,
        &forged_plain,
        scanned,
        Err(NOT_CONFIRMED),
    ));
    cases.push(box_accept_case(
        "box-accept/the-number-confirmed-the-approver",
        "The person picked Ada's phone's number on the laptop: a plain box from that key, and only that key, is accepted.",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &sealed,
        Vouched {
            confirmed_approver_key: Some(&approver),
            ..Vouched::default()
        },
        Ok(&ACCOUNT_KEY),
    ));
    cases.push(box_accept_case(
        "box-accept/another-approver-was-confirmed",
        "The person confirmed Ada's phone; the box is from another listed device. Confirming one approver vouches for no other.",
        &RECIPIENT_SEED,
        &public(&FORGER_SEED),
        DEVICE_ID,
        &forged_plain,
        Vouched {
            confirmed_approver_key: Some(&approver),
            ..Vouched::default()
        },
        Err(NOT_CONFIRMED),
    ));
    cases.push(box_accept_case(
        "box-accept/the-device-allows-server-approvals",
        "The device's own switch (a test server it was built for, or a sign-in with a fictional number): a plain box from any listed approver is accepted.",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &sealed,
        Vouched {
            server_approval_allowed: true,
            ..Vouched::default()
        },
        Ok(&ACCOUNT_KEY),
    ));
    cases.push(box_accept_case(
        "box-accept/the-switch-still-checks-the-box",
        "The switch skips the person's confirmation, not the cryptography: a box claimed for another approver still does not open.",
        &RECIPIENT_SEED,
        &public(&WRONG_APPROVER_SEED),
        DEVICE_ID,
        &sealed,
        Vouched {
            server_approval_allowed: true,
            ..Vouched::default()
        },
        Err(BOX_DOES_NOT_OPEN),
    ));

    // ---- boxAcceptHybrid: the post-quantum box --------------------------
    let hybrid = unhex_str(HYBRID_BOX_HEX);
    assert_eq!(hybrid.len(), ACCOUNT_KEY_BOX_HYBRID_BYTES);
    let posted = Hybrid {
        vouched: Vouched {
            confirmed_approver_key: Some(&approver),
            ..Vouched::default()
        },
        link_key_seed: Some(&LINK_KEY_SEED),
    };
    let hybrid_does_not_open = "does not open for this device, approver, link key and device id";
    cases.push(box_accept_hybrid_case(
        "box-accept-hybrid/the-number-confirmed-the-approver",
        "The laptop posted an X-Wing link key (seed 5a5a..) with its nonce, signed by its own key; Ada's phone, whose number the person picked, sealed a version-3 box to it. The box key mixes both X25519 agreements with the X-Wing secret, so recording the pairing today and breaking X25519 later opens nothing.",
        &approver,
        &hybrid,
        posted,
        Ok(&ACCOUNT_KEY),
    ));
    cases.push(box_accept_hybrid_case(
        "box-accept-hybrid/the-switch-does-not-open-an-unconfirmed-version-3-box",
        "The device's own switch opens a version-1 box from any listed approver, never a version-3 box: that opens only from the approver whose number the person picked here.",
        &approver,
        &hybrid,
        Hybrid {
            vouched: Vouched {
                server_approval_allowed: true,
                ..Vouched::default()
            },
            ..posted
        },
        Err(NOT_CONFIRMED),
    ));
    cases.push(box_accept_hybrid_case(
        "box-accept-hybrid/an-unconfirmed-approver",
        "A sound box, but the person confirmed no approver on this device: refused before any cryptography.",
        &approver,
        &hybrid,
        Hybrid {
            vouched: Vouched::default(),
            ..posted
        },
        Err(NOT_CONFIRMED),
    ));
    cases.push(box_accept_hybrid_case(
        "box-accept-hybrid/this-device-posted-no-link-key",
        "A version-3 box on a device that posted no link key has nothing to open it with.",
        &approver,
        &hybrid,
        Hybrid {
            link_key_seed: None,
            ..posted
        },
        Err("a box sealed to a link key, and this device posted none"),
    ));
    cases.push(box_accept_hybrid_case(
        "box-accept-hybrid/sealed-to-another-link-key",
        "THE case for the link key. A server that swapped in a link key of its own (seed 5b5b..) cannot make the approver's box open on the laptop: the laptop opens with the seed it drew, and the box does not open.",
        &approver,
        &hybrid,
        Hybrid {
            link_key_seed: Some(&WRONG_LINK_KEY_SEED),
            ..posted
        },
        Err(hybrid_does_not_open),
    ));
    let mut bent_enc = hybrid.clone();
    bent_enc[1 + 32 + 7] ^= 0x01;
    cases.push(box_accept_hybrid_case(
        "box-accept-hybrid/a-bent-encapsulation",
        "One bit of the X-Wing encapsulation flipped: the KEM secret differs, and the encapsulation is also the AES-GCM associated data, so it does not open.",
        &approver,
        &bent_enc,
        posted,
        Err(hybrid_does_not_open),
    ));
    cases.push(box_accept_hybrid_case(
        "box-accept-hybrid/one-byte-short",
        "A version-3 box is exactly 1213 bytes.",
        &approver,
        &hybrid[..hybrid.len() - 1],
        posted,
        Err("a version-3 account key box must be exactly 1213 bytes, got 1212"),
    ));
    cases.push(box_accept_hybrid_case(
        "box-accept-hybrid/an-x25519-only-box",
        "THE downgrade. A version-1 box from the confirmed approver is refused, so a server that strips the link key from the pairing gets no X25519-only box accepted by this door.",
        &approver,
        &sealed,
        posted,
        Err("an X25519-only account key box, and this build takes only the post-quantum box"),
    ));
    cases.push(box_accept_hybrid_case(
        "box-accept-hybrid/an-x25519-only-box-under-the-switch",
        "The approvals a test server makes itself seal version 1; the device's own switch still lets one open.",
        &approver,
        &sealed,
        Hybrid {
            vouched: Vouched {
                server_approval_allowed: true,
                ..Vouched::default()
            },
            link_key_seed: None,
        },
        Ok(&ACCOUNT_KEY),
    ));

    // ---- transferKeyOpen: a hand-off's key, sealed to its device ----------
    let transfer =
        transfer_key_seal_with(&recipient, DEVICE_ID, &TRANSFER_KEY, &EPHEMERAL, &BOX_NONCE)
            .unwrap();
    assert_eq!(transfer.len(), 93);
    cases.push(transfer_key_open_case(
        "transfer-key-open/phone-to-laptop",
        "Ada's phone seals the key of the history it hands her new laptop (seed 3333..) to the laptop's signing key and row.",
        &RECIPIENT_SEED,
        DEVICE_ID,
        &transfer,
        Ok(&TRANSFER_KEY),
    ));
    cases.push(transfer_key_open_case(
        "transfer-key-open/another-device",
        "THE case. Another device of the account, one removed but still holding the account key, is handed the same note: its own seed does not open the box.",
        &BYSTANDER_SEED,
        DEVICE_ID,
        &transfer,
        Err(TRANSFER_DOES_NOT_OPEN),
    ));
    cases.push(transfer_key_open_case(
        "transfer-key-open/another-row",
        "The box replayed onto another device row: the row id is in the HKDF info.",
        &RECIPIENT_SEED,
        "0f8e2b1c-6a4d-4e3f-9b2a-7c5d1e0f3a9c",
        &transfer,
        Err(TRANSFER_DOES_NOT_OPEN),
    ));
    let mut tampered = transfer.clone();
    tampered[1] ^= 0x01;
    cases.push(transfer_key_open_case(
        "transfer-key-open/tampered-ephemeral",
        "E is the AEAD's associated data as well as the agreement's other half.",
        &RECIPIENT_SEED,
        DEVICE_ID,
        &tampered,
        Err(TRANSFER_DOES_NOT_OPEN),
    ));
    let mut tampered = transfer.clone();
    tampered[92] ^= 0x01;
    cases.push(transfer_key_open_case(
        "transfer-key-open/tampered-tag",
        "One bit of the tag flipped.",
        &RECIPIENT_SEED,
        DEVICE_ID,
        &tampered,
        Err(TRANSFER_DOES_NOT_OPEN),
    ));
    let mut bad_version = transfer.clone();
    bad_version[0] = 0x02;
    cases.push(transfer_key_open_case(
        "transfer-key-open/bad-version-byte",
        "0x01 is the only transfer box format.",
        &RECIPIENT_SEED,
        DEVICE_ID,
        &bad_version,
        Err("unknown transfer key box format version 0x02"),
    ));
    cases.push(transfer_key_open_case(
        "transfer-key-open/truncated",
        "A transfer box is exactly 93 bytes.",
        &RECIPIENT_SEED,
        DEVICE_ID,
        &transfer[..92],
        Err("a transfer key box must be exactly 93 bytes, got 92"),
    ));
    cases.push(transfer_key_open_case(
        "transfer-key-open/empty-device-id",
        "A device id is never empty.",
        &RECIPIENT_SEED,
        "",
        &transfer,
        Err("a device_id must not be empty"),
    ));
    cases.push(transfer_key_open_case(
        "transfer-key-open/an-account-key-box",
        "An account-key box to the same device and row, the same length and leading byte: its own domain keeps it shut here.",
        &RECIPIENT_SEED,
        DEVICE_ID,
        &sealed,
        Err(TRANSFER_DOES_NOT_OPEN),
    ));
    cases.push(box_open_case(
        "box-open/a-transfer-key-box",
        "And the reverse: a transfer box never opens as the account key.",
        &RECIPIENT_SEED,
        &approver,
        DEVICE_ID,
        &transfer,
        Err(BOX_DOES_NOT_OPEN),
    ));

    // ---- Self-notes: the same codec under another domain ----------------
    let read_note = br#"{"peachy":"read","v":1,"g":"5b0f5a52-8a55-4a5b-9d59-1b9a7a3f0c11","m":"0f3c6d2e-1111-4222-8333-944455556666","at":1790000000000}"#;
    let v_note = note_seal_with(&ACCOUNT_KEY, &NOTE_ID, read_note, &nonce(0x70)).unwrap();
    cases.push(store_open_case(
        "store-open/a-self-note",
        "A self-note under the same id and key is not a store record.",
        &ACCOUNT_KEY,
        &NOTE_ID,
        &v_note,
        Err(DOES_NOT_OPEN),
    ));

    // ---- Signed self-notes: which device sent it, and when ---------------
    let phone = public(&APPROVER_SEED);
    let signed = note_seal_signed_with(
        &ACCOUNT_KEY,
        &NOTE_ID,
        read_note,
        PHONE_DEVICE_ID,
        NOTE_ISSUED_AT,
        &APPROVER_SEED,
        &nonce(0x72),
    )
    .unwrap();
    cases.push(note_sender_case(
        "note-sender/read-note",
        "A signed note names the device that sent it; the receiver looks that device up in its own account's device list.",
        &NOTE_ID,
        &signed,
        Ok(PHONE_DEVICE_ID),
    ));
    cases.push(note_sender_case(
        "note-sender/an-unsigned-note",
        "A version-1 note names nobody: refused.",
        &NOTE_ID,
        &v_note,
        Err("unsigned"),
    ));
    cases.push(note_sender_case(
        "note-sender/wrong-id",
        "A signed note served under another note's id.",
        &CONTACT_ID,
        &signed,
        Err(DOES_NOT_OPEN),
    ));
    cases.push(note_open_signed_case(
        "note-open-signed/read-note",
        "The phone's read note, opened against the phone's own key, at the moment it was sent.",
        &NOTE_ID,
        &signed,
        PHONE_DEVICE_ID,
        &phone,
        NOTE_ISSUED_AT,
        Ok(read_note),
    ));
    cases.push(note_open_signed_case(
        "note-open-signed/seven-days-on",
        "The oldest a note may be: exactly seven days after it was issued.",
        &NOTE_ID,
        &signed,
        PHONE_DEVICE_ID,
        &phone,
        NOTE_ISSUED_AT + NOTE_MAX_AGE_MS,
        Ok(read_note),
    ));
    cases.push(note_open_signed_case(
        "note-open-signed/stale",
        "A millisecond past seven days: a note the server kept back and delivers again is refused.",
        &NOTE_ID,
        &signed,
        PHONE_DEVICE_ID,
        &phone,
        NOTE_ISSUED_AT + NOTE_MAX_AGE_MS + 1,
        Err("stale"),
    ));
    cases.push(note_open_signed_case(
        "note-open-signed/dated-ahead",
        "Dated more than ten minutes ahead of the receiver's clock.",
        &NOTE_ID,
        &signed,
        PHONE_DEVICE_ID,
        &phone,
        NOTE_ISSUED_AT - NOTE_MAX_AHEAD_MS - 1,
        Err("dated ahead"),
    ));
    cases.push(note_open_signed_case(
        "note-open-signed/another-devices-key",
        "Checked against the key of a device that did not send it.",
        &NOTE_ID,
        &signed,
        PHONE_DEVICE_ID,
        &public(&BYSTANDER_SEED),
        NOTE_ISSUED_AT,
        Err("does not verify"),
    ));
    cases.push(note_open_signed_case(
        "note-open-signed/names-another-sender",
        "Opened for a device the note does not name.",
        &NOTE_ID,
        &signed,
        DEVICE_ID,
        &phone,
        NOTE_ISSUED_AT,
        Err("names device"),
    ));
    let forged = note_seal_signed_with(
        &ACCOUNT_KEY,
        &NOTE_ID,
        read_note,
        PHONE_DEVICE_ID,
        NOTE_ISSUED_AT,
        &FORGER_SEED,
        &nonce(0x73),
    )
    .unwrap();
    cases.push(note_open_signed_case(
        "note-open-signed/a-key-holder-signs-as-the-phone",
        "A removed device keeps the account key: it can seal a note that names the phone, but cannot sign one with the phone's key.",
        &NOTE_ID,
        &forged,
        PHONE_DEVICE_ID,
        &phone,
        NOTE_ISSUED_AT,
        Err("does not verify"),
    ));
    let fixture = Fixture {
        version: FORMAT_VERSION,
        about: vec![
            "The golden fixture for account_store: the encrypted account store's crypto,",
            "mls/core/src/account_store.rs (read its header for the why).",
            "GENERATED by mls/core/tests/account_store_fixture.rs from fixed nonces and a",
            "fixed ephemeral, with the Rust-only *_with seal variants. Do not edit by hand;",
            "regenerate with PEACHY_WRITE_ACCOUNT_STORE_FIXTURE=1 (see that file's header).",
            "",
            "Only OPENING is golden: a real seal takes a fresh nonce every time, so four",
            "clients must agree on what a given value opens to and on every refusal.",
            "Every expected plaintext / account key is the INPUT the generator sealed.",
            "",
            "Replayed in Rust (mls/core/tests/account_store_fixture.rs), wasm",
            "(mls/wasm/tests/node/account-store.test.mjs) and Swift",
            "(AccountStoreFixtureTests.swift), and in Peachy's Android client in Kotlin,",
            "each through the shared fixture door and the binding's own doors where it",
            "has them (storeOpen, accountKeyAcceptHybrid).",
            "",
            "KEY MATERIAL IS SYNTHESISED, NEVER REAL:",
            "  a1a1..a1  the account key;  a2a2..a2  another account's key",
            "  1111..11 (16)  a contact record's id;  2222..22 (16)  a chat record's id",
            "  0000..00 (16)  MANIFEST_ID",
            "  1111..11 (32)  Ada's phone, the APPROVING device's Ed25519 seed",
            "  3333..33  the new laptop, the RECIPIENT's seed",
            "  4444..44  a device that approved nothing;  5555..55  a bystander device",
            "  7777..77  a made-up static key (the forgery case)",
            "  5e5e..5e  the box's ephemeral X25519 secret;  6666..66  its nonce",
            "  5f5f..5f  a link secret, for the inner opener's version-2 cases (no client",
            "            sends one);  6060..60  a guessed one",
            "  0101.., 0202.. ... (12)  the record nonces;  7070.. to 7373..  the note nonces",
            "  9999..99 (16)  a self-note's id;  6a1c0e52-..  the phone's device id",
            "",
            "boxAccept: the crate's inner opener (account_key_accept in",
            "mls/core/src/account_store.rs), replayed through the fixture door only. A",
            "version-2 box opens only with the link secret handed in, and no client seals",
            "one; a version-1 box only from the approver whose number the person picked",
            "on the device, or under the device's own switch for server-run approvals.",
            "",
            "boxAcceptHybrid: the new device's door (account_key_accept_hybrid). A",
            "version-3 box opens only from the approver whose number the person picked;",
            "the device's own switch never opens one. A version-1 box opens only under the",
            "device's own switch, from any listed approver, and never otherwise, even from",
            "a confirmed approver. A version-2 box never opens there.",
            "",
            "noteSender / noteOpenSigned: the signed note (format 0x02, domain",
            "\"peachy self note v2\"), sealed and signed by the sending device. noteSender",
            "says which device the note claims sent it; noteOpenSigned believes it only",
            "under that device's key (deviceId, senderKeyHex), issued at most seven days",
            "before nowMs and at most ten minutes after it.",
            "",
            "transferKeyOpen: the key of a history hand-off's document, sealed to the",
            "device it is handed to (domain \"peachy transfer key v1\"). It opens only with",
            "that device's seed and its own device id; the account key is no help, and an",
            "account-key box never opens as a transfer box nor the reverse. 7c7c..7c is",
            "the attachment key.",
            "expectError is a substring of the refusal's message.",
        ],
        cases,
    };
    let mut text = serde_json::to_string_pretty(&fixture).expect("serialises");
    text.push('\n');
    text
}

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("mls/fixtures/account-store.json is valid JSON")
}

fn cases(root: &Value) -> &Vec<Value> {
    root["cases"].as_array().expect("`cases` is an array")
}

#[test]
fn the_committed_fixture_is_what_the_generator_writes() {
    let generated = generate();
    if std::env::var_os("PEACHY_WRITE_ACCOUNT_STORE_FIXTURE").is_some() {
        std::fs::write(FIXTURE_PATH, &generated).expect("writes the fixture");
        return;
    }
    assert!(
        FIXTURE == generated,
        "mls/fixtures/account-store.json is not what the generator writes. Either the \
         crypto changed (every client changed with it; regenerate and say so) or the file \
         was edited by hand. Regenerate: see this file's header."
    );
}

#[test]
fn the_fixture_declares_the_format_this_build_reads() {
    let root = fixture();
    assert_eq!(root["version"].as_u64(), Some(u64::from(FORMAT_VERSION)));
    assert!(
        cases(&root).len() >= 30,
        "only {} cases — the fixture shrank or stopped parsing",
        cases(&root).len()
    );
    for case in cases(&root) {
        assert_eq!(
            case["kind"].as_str(),
            Some("account_store"),
            "{}",
            case["id"]
        );
        assert_ne!(
            case["expect"].is_null(),
            case["expectError"].is_null(),
            "case {} needs exactly one of `expect` and `expectError`",
            case["id"]
        );
    }
}

#[test]
fn every_case_gets_the_verdict_it_expects() {
    let root = fixture();
    let mut ids = BTreeSet::new();
    let mut failures = Vec::new();

    for case in cases(&root) {
        let id = case["id"].as_str().unwrap_or("<no id>").to_string();
        assert!(ids.insert(id.clone()), "two cases share the id {id:?}");
        let outcome = evaluate_case_json(&case.to_string());
        match case["expectError"].as_str() {
            Some(expected) => match outcome {
                Ok(verdict) => failures.push(format!(
                    "  {id}\n    expected a refusal naming {expected:?}\n    actual   {verdict}"
                )),
                Err(err) if !err.to_string().contains(expected) => failures.push(format!(
                    "  {id}\n    expected a refusal naming {expected:?}\n    actual   {err}"
                )),
                Err(_) => {}
            },
            None => match outcome {
                Err(err) => failures.push(format!(
                    "  {id}\n    expected {}\n    actual   refused: {err}",
                    case["expect"]
                )),
                Ok(verdict) => {
                    let actual: Value = serde_json::from_str(&verdict).expect("JSON");
                    if actual != case["expect"] {
                        failures.push(format!(
                            "  {id}\n    expected {}\n    actual   {actual}",
                            case["expect"]
                        ));
                    }
                }
            },
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases disagree with mls/core/src/account_store.rs:\n{}",
        failures.len(),
        cases(&root).len(),
        failures.join("\n")
    );
}

#[test]
fn every_open_case_agrees_with_the_public_functions_directly() {
    // The door above goes through the fixture harness; this goes through the
    // functions every binding actually wraps.
    let root = fixture();
    let unhex = |v: &Value| hex::decode(v.as_str().expect("hex string")).expect("hex");
    for case in cases(&root) {
        let expected_error = case["expectError"].as_str();
        match case["call"].as_str() {
            Some("storeOpen") => {
                let outcome = store_open(
                    &unhex(&case["accountKeyHex"]),
                    &unhex(&case["idHex"]),
                    &unhex(&case["valueHex"]),
                );
                match expected_error {
                    Some(message) => assert!(
                        outcome
                            .as_ref()
                            .err()
                            .is_some_and(|e| e.to_string().contains(message)),
                        "{}: {outcome:?}",
                        case["id"]
                    ),
                    None => assert_eq!(
                        outcome.expect("opens"),
                        unhex(&case["expect"]["plaintextHex"]),
                        "{}",
                        case["id"]
                    ),
                }
            }
            Some("noteSender") => {
                let outcome = note_sender(
                    &unhex(&case["accountKeyHex"]),
                    &unhex(&case["idHex"]),
                    &unhex(&case["valueHex"]),
                );
                match expected_error {
                    Some(message) => assert!(
                        outcome
                            .as_ref()
                            .err()
                            .is_some_and(|e| e.to_string().contains(message)),
                        "{}: {outcome:?}",
                        case["id"]
                    ),
                    None => assert_eq!(
                        outcome.expect("a sender"),
                        case["expect"]["senderDeviceId"].as_str().expect("sender"),
                        "{}",
                        case["id"]
                    ),
                }
            }
            Some("noteOpenSigned") => {
                let outcome = note_open_signed(
                    &unhex(&case["accountKeyHex"]),
                    &unhex(&case["idHex"]),
                    &unhex(&case["valueHex"]),
                    case["deviceId"].as_str().expect("deviceId"),
                    &unhex(&case["senderKeyHex"]),
                    case["nowMs"].as_i64().expect("nowMs"),
                );
                match expected_error {
                    Some(message) => assert!(
                        outcome
                            .as_ref()
                            .err()
                            .is_some_and(|e| e.to_string().contains(message)),
                        "{}: {outcome:?}",
                        case["id"]
                    ),
                    None => assert_eq!(
                        outcome.expect("opens"),
                        unhex(&case["expect"]["plaintextHex"]),
                        "{}",
                        case["id"]
                    ),
                }
            }
            Some("transferKeyOpen") => {
                let outcome = transfer_key_open(
                    &unhex(&case["recipientSeedHex"]),
                    case["deviceId"].as_str().expect("deviceId"),
                    &unhex(&case["boxHex"]),
                );
                match expected_error {
                    Some(message) => assert!(
                        outcome
                            .as_ref()
                            .err()
                            .is_some_and(|e| e.to_string().contains(message)),
                        "{}: {outcome:?}",
                        case["id"]
                    ),
                    None => assert_eq!(
                        outcome.expect("opens").to_vec(),
                        unhex(&case["expect"]["transferKeyHex"]),
                        "{}",
                        case["id"]
                    ),
                }
            }
            // `boxAccept` has no public function of its own (the door a client
            // calls is `account_key_accept_hybrid`, which takes it in): it is
            // replayed through the fixture door above.
            Some(call @ ("boxOpen" | "boxAcceptHybrid")) => {
                let optional = |v: &Value| if v.is_null() { Vec::new() } else { unhex(v) };
                let outcome = if call == "boxAcceptHybrid" {
                    account_key_accept_hybrid(
                        &unhex(&case["recipientSeedHex"]),
                        &unhex(&case["approverKeyHex"]),
                        case["deviceId"].as_str().expect("deviceId"),
                        &unhex(&case["boxHex"]),
                        &optional(&case["linkKeySeedHex"]),
                        &optional(&case["confirmedApproverKeyHex"]),
                        case["serverApprovalAllowed"].as_bool().unwrap_or(false),
                    )
                } else {
                    account_key_open(
                        &unhex(&case["recipientSeedHex"]),
                        &unhex(&case["approverKeyHex"]),
                        case["deviceId"].as_str().expect("deviceId"),
                        &unhex(&case["boxHex"]),
                    )
                };
                match expected_error {
                    Some(message) => assert!(
                        outcome
                            .as_ref()
                            .err()
                            .is_some_and(|e| e.to_string().contains(message)),
                        "{}: {outcome:?}",
                        case["id"]
                    ),
                    None => assert_eq!(
                        outcome.expect("opens").to_vec(),
                        unhex(&case["expect"]["accountKeyHex"]),
                        "{}",
                        case["id"]
                    ),
                }
            }
            _ => {}
        }
    }
}

#[test]
fn every_call_is_reached_and_every_refusal_is_covered() {
    let root = fixture();
    let reached: BTreeSet<&str> = cases(&root)
        .iter()
        .filter_map(|case| case["call"].as_str())
        .collect();
    for call in CALLS {
        assert!(reached.contains(call), "no case calls {call:?}");
    }
    for case in cases(&root) {
        let call = case["call"].as_str().unwrap_or_default();
        assert!(
            CALLS.contains(&call),
            "case {}: no such call {call:?}",
            case["id"]
        );
    }
    // The six refusals the design names, each present by id.
    let ids: BTreeSet<&str> = cases(&root)
        .iter()
        .filter_map(|case| case["id"].as_str())
        .collect();
    for required in [
        "store-open/wrong-id",
        "store-open/tampered-ciphertext",
        "box-open/wrong-approver-key",
        "box-open/wrong-device-id",
        "store-open/bad-version-byte",
        "box-open/bad-version-byte",
        "store-open/id-of-15-bytes",
        "record-key/id-of-15-bytes",
        "store-open/empty-plaintext",
        "store-open/255-bytes",
        "store-open/256-bytes",
        "store-open/multi-bucket",
        "store-open/manifest",
        "store-open/a-self-note",
        "box-accept/the-server-guessed-a-link-secret",
        "box-accept/the-server-ran-the-approver",
        "box-accept/another-approver-was-confirmed",
        "box-accept-hybrid/sealed-to-another-link-key",
        "box-accept-hybrid/an-x25519-only-box",
        "note-sender/read-note",
        "note-sender/an-unsigned-note",
        "note-open-signed/read-note",
        "note-open-signed/stale",
        "note-open-signed/dated-ahead",
        "note-open-signed/another-devices-key",
        "note-open-signed/a-key-holder-signs-as-the-phone",
        "transfer-key-open/phone-to-laptop",
        "transfer-key-open/another-device",
        "transfer-key-open/another-row",
        "transfer-key-open/an-account-key-box",
        "box-open/a-transfer-key-box",
    ] {
        assert!(ids.contains(required), "the fixture lost {required:?}");
    }
}

#[test]
fn the_domains_are_what_the_design_pins() {
    assert_eq!(STORE_RECORD_KEY_DOMAIN, "peachy store v1");
    assert_eq!(ACCOUNT_KEY_BOX_DOMAIN, "peachy account key v1");
    assert_eq!(ACCOUNT_KEY_BOX_LINKED_DOMAIN, "peachy account key v2");
    assert_eq!(MANIFEST_ID, [0u8; 16]);
    assert_eq!(NOTE_KEY_DOMAIN, "peachy self note v1");
    assert_eq!(NOTE_SIGNED_KEY_DOMAIN, "peachy self note v2");
    assert_eq!(NOTE_SIGNATURE_DOMAIN, "peachy-self-note-v2");
    assert_eq!(TRANSFER_KEY_DOMAIN, "peachy transfer key v1");
    assert_ne!(
        note_key(&ACCOUNT_KEY, &CONTACT_ID).unwrap(),
        record_key(&ACCOUNT_KEY, &CONTACT_ID).unwrap()
    );
}

#[test]
fn the_random_doors_round_trip() {
    let key = generate_account_key().expect("a key");
    assert_ne!(key, generate_account_key().expect("another key"));
    let value = store_seal(&key, &CONTACT_ID, b"hello").expect("seals");
    assert_eq!(
        store_open(&key, &CONTACT_ID, &value).expect("opens"),
        b"hello"
    );
    let signed = note_seal_signed(
        &key,
        &NOTE_ID,
        b"hi",
        PHONE_DEVICE_ID,
        NOTE_ISSUED_AT,
        &APPROVER_SEED,
    )
    .expect("seals");
    assert_eq!(
        note_open_signed(
            &key,
            &NOTE_ID,
            &signed,
            PHONE_DEVICE_ID,
            &public(&APPROVER_SEED),
            NOTE_ISSUED_AT
        )
        .expect("opens"),
        b"hi"
    );
    assert!(store_open(&key, &NOTE_ID, &signed).is_err());

    let sealed =
        account_key_seal(&APPROVER_SEED, &public(&RECIPIENT_SEED), DEVICE_ID, &key).expect("box");
    assert_eq!(
        account_key_open(&RECIPIENT_SEED, &public(&APPROVER_SEED), DEVICE_ID, &sealed)
            .expect("opens"),
        key
    );
    let linked = account_key_seal_linked(
        &APPROVER_SEED,
        &public(&RECIPIENT_SEED),
        DEVICE_ID,
        &key,
        &QR_LINK_KEY,
    )
    .expect("box");
    // The door a client calls never opens a linked box.
    assert!(account_key_accept_hybrid(
        &RECIPIENT_SEED,
        &public(&APPROVER_SEED),
        DEVICE_ID,
        &linked,
        &[],
        &public(&APPROVER_SEED),
        true
    )
    .is_err());
    let transfer = transfer_key_seal(&public(&RECIPIENT_SEED), DEVICE_ID, &key).expect("box");
    assert_eq!(
        transfer_key_open(&RECIPIENT_SEED, DEVICE_ID, &transfer).expect("opens"),
        key
    );
    assert!(transfer_key_open(&BYSTANDER_SEED, DEVICE_ID, &transfer).is_err());
}

#[test]
fn an_unknown_call_is_an_error_and_not_a_verdict() {
    let err =
        evaluate_case_json(r#"{"kind":"account_store","call":"storeSeal"}"#).expect_err("refused");
    assert!(err.to_string().contains("storeSeal"), "{err}");
    assert!(err.to_string().contains("boxOpen"), "{err}");

    let err = evaluate_case_json(r#"{"kind":"account_store","call":"storeOpen","idHex":"00"}"#)
        .expect_err("a missing field is named");
    assert!(err.to_string().contains("`accountKeyHex`"), "{err}");
}
