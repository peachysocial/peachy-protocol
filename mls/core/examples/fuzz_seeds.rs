// SPDX-License-Identifier: MIT
//! Write a starting corpus for every fuzz target in `mls/fuzz` from the golden
//! fixtures in `mls/fixtures`, each input laid out as its target reads it
//! (the layouts are in each target's header). docs/mls-core.md
//! §Fuzzing.
//!
//! ```sh
//! # from the repository root
//! cargo run --manifest-path mls/Cargo.toml -p peachy-mls-core --features fixture \
//!   --example fuzz_seeds -- mls/fuzz/corpus
//! ```
//!
//! writes `<dir>/<target>/<sha-256 of the input>` and prints how many inputs
//! each target got. `mls/fuzz/corpus` is where `cargo fuzz run` looks by
//! default, and it is ignored by version control; run it again after a fixture
//! changes. `call_ring_step` gets none: its input is a stream of small
//! alphabets no fixture is written in. The targets that mutate a real group's
//! own message, Welcome or key package get the layouts that reach them, and
//! the targets that seal before they mutate get what the fixtures seal, in
//! the layout that seals it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use openmls::prelude::{Extensions, GroupContext};
use peachy_mls_core::group_meta::group_context_extensions_with_meta;
use peachy_mls_core::hint::hint_aad;
use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    account_identity_public_key, Client, ClientConfig, FixedClock, PeachyStorage,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tls_codec::Serialize as _;

type Seeds = BTreeMap<&'static str, Vec<Vec<u8>>>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: fuzz_seeds <corpus directory>")?;
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    let load = |name: &str| -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        let text = std::fs::read_to_string(fixtures.join(name))?;
        let json: Value = serde_json::from_str(&text)?;
        Ok(json["cases"].as_array().cloned().unwrap_or_default())
    };

    let mut seeds = Seeds::new();
    envelopes(&load("rosters.json")?, &load("calls.json")?, &mut seeds);
    calls(&load("calls.json")?, &mut seeds);
    credentials(&load("credentials.json")?, &mut seeds)?;
    join_requests(&load("join-request.json")?, &mut seeds);
    account_store(&load("account-store.json")?, &mut seeds);
    device_link(&load("device-link.json")?, &mut seeds);
    group_meta(&load("formats/group-meta.json")?, &mut seeds)?;
    let hints: Value = serde_json::from_str(&std::fs::read_to_string(
        fixtures.join("formats/content-hint.json"),
    )?)?;
    content_hint(&hints, &mut seeds)?;
    welcome_frame(&load("welcome-frame.json")?, &mut seeds);
    live_objects(&mut seeds)?;
    media_grants(&load("calls.json")?, &mut seeds);
    let typing: Value = serde_json::from_str(&std::fs::read_to_string(
        fixtures.join("formats/typing.json"),
    )?)?;
    typing_frames(&typing, &mut seeds);
    epoch_envelopes(&load("rosters.json")?, &mut seeds);
    device_seals(&load("device-seal.json")?, &mut seeds);
    commit_entries(
        &load("carried-commit.json")?,
        &load("steward.json")?,
        &mut seeds,
    );
    steward_frames(&load("steward.json")?, &mut seeds);
    gap_blocks(&load("welcome-frame.json")?, &mut seeds);
    account_signatures(&load("device-link.json")?, &mut seeds);
    signed_account_store(&load("account-store.json")?, &mut seeds);
    device_link_exchange(&load("device-link.json")?, &mut seeds);
    server_key_lists(&mut seeds)?;
    own_device_lists(&mut seeds)?;
    resend_secrets(&mut seeds);

    for (target, inputs) in &seeds {
        let dir = out.join(target);
        std::fs::create_dir_all(&dir)?;
        for input in inputs {
            std::fs::write(dir.join(hex::encode(Sha256::digest(input))), input)?;
        }
        println!("{target}: {} inputs", inputs.len());
    }
    Ok(())
}

fn str_of<'a>(case: &'a Value, path: &str) -> Option<&'a str> {
    path.split('.')
        .try_fold(case, |v, key| v.get(key))?
        .as_str()
}

fn hex_of(case: &Value, path: &str) -> Option<Vec<u8>> {
    hex::decode(str_of(case, path)?).ok()
}

fn int_of(case: &Value, path: &str) -> Option<i64> {
    path.split('.')
        .try_fold(case, |v, key| v.get(key))?
        .as_i64()
}

fn call_of(case: &Value) -> &str {
    str_of(case, "call").unwrap_or("")
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn add(seeds: &mut Seeds, target: &'static str, input: Vec<u8>) {
    seeds.entry(target).or_default().push(input);
}

fn envelopes(rosters: &[Value], calls: &[Value], seeds: &mut Seeds) {
    for case in rosters.iter().chain(calls) {
        for path in ["envelopeHex", "expect.envelopeHex"] {
            if let Some(envelope) = hex_of(case, path) {
                add(seeds, "envelope_open", envelope.clone());
                add(seeds, "call_envelope_open", cat(&[&[0], &envelope]));
            }
        }
        let kind = int_of(case, "envelopeKind").or_else(|| int_of(case, "expect.kind"));
        if let (Some(kind), Some(inner)) = (kind, hex_of(case, "innerHex")) {
            add(
                seeds,
                "envelope_roundtrip",
                cat(&[&[kind as u8, 0, 0], &inner]),
            );
        }
    }
}

fn calls(cases: &[Value], seeds: &mut Seeds) {
    for case in cases {
        match call_of(case) {
            "decode" | "encode" => {
                for path in ["bytesHex", "expect.bytesHex"] {
                    if let Some(bytes) = hex_of(case, path) {
                        add(seeds, "call_signal_decode", bytes.clone());
                        // Live-sealed unsigned as Ada, Bo and Cy, and
                        // signed by Bo and by Cy.
                        for mode in [2u8, 6, 10, 3, 11] {
                            add(seeds, "call_envelope_open", cat(&[&[mode], &bytes]));
                        }
                    }
                }
                let given = case.get("signal");
                let expected = case.get("expect").and_then(|e| e.get("signal"));
                for signal in [given, expected]
                    .into_iter()
                    .flatten()
                    .filter(|s| s.is_object())
                {
                    add(seeds, "call_signal_json", signal.to_string().into_bytes());
                }
            }
            "openLive" | "sealLive" => {
                for path in ["innerHex", "expect.innerHex"] {
                    if let Some(frame) = hex_of(case, path) {
                        add(seeds, "call_live_frame_open", frame);
                    }
                }
            }
            "envelope" => {
                if let Some(inner) = hex_of(case, "innerHex") {
                    add(seeds, "call_envelope_open", cat(&[&[1], &inner]));
                }
            }
            _ => {}
        }
    }
}

fn seed32(case: &Value, path: &str) -> Option<[u8; 32]> {
    hex_of(case, path)?.try_into().ok()
}

fn credentials(cases: &[Value], seeds: &mut Seeds) -> Result<(), Box<dyn std::error::Error>> {
    for case in cases {
        if let Some(token) = str_of(case, "token") {
            add(seeds, "credential_parse", cat(&[&[0], token.as_bytes()]));
        }
        // The plain mints: a signer, a device and a lifetime, nothing altered.
        let Some(mint) = case.get("mint") else {
            continue;
        };
        let plain = [
            "prefix",
            "extra",
            "tamper",
            "version",
            "kid",
            "deviceKey",
            "accountKey",
            "accountSigner",
            "actorIdFill",
            "accountSigOmitted",
        ]
        .iter()
        .all(|key| mint.get(key).is_none());
        let (Some(signer), Some(device), Some(actor), Some(device_id), Some(iat), Some(exp)) = (
            seed32(mint, "signerSeed"),
            seed32(mint, "deviceSeed"),
            str_of(mint, "actorId"),
            str_of(mint, "deviceId"),
            int_of(mint, "issuedAt"),
            int_of(mint, "expiresAt"),
        ) else {
            continue;
        };
        if !plain {
            continue;
        }
        // A case about a malformed field (an empty actor id, say) mints a token
        // that does not parse; its payload still seeds the signed mode.
        let Ok(token) = TestIssuer::from_seed(&signer).issue(
            actor,
            device_id,
            &device_key_pair(&device).1,
            iat,
            exp,
        ) else {
            continue;
        };
        add(seeds, "credential_parse", cat(&[&[0], &token]));
        let payload = token.split(|&b| b == b'.').nth(1).unwrap_or_default();
        if let Ok(payload) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) {
            add(seeds, "credential_parse", cat(&[&[1], &payload]));
        }
    }
    Ok(())
}

fn join_requests(cases: &[Value], seeds: &mut Seeds) {
    for case in cases {
        if let Some(proof) = hex_of(case, "proofHex").or_else(|| hex_of(case, "expect.proofHex")) {
            add(seeds, "join_request_check", cat(&[&[0], &proof]));
        }
        for prefix in ["", "proof."] {
            if let (Some(at), Some(nonce)) = (
                int_of(case, &format!("{prefix}issuedAt")),
                hex_of(case, &format!("{prefix}nonceHex")),
            ) {
                add(
                    seeds,
                    "join_request_check",
                    cat(&[&[1], &at.to_be_bytes(), &nonce]),
                );
                add(
                    seeds,
                    "join_request_check",
                    cat(&[&[1], &at.to_be_bytes(), &nonce, &[0, 9]]),
                );
            }
        }
    }
}

fn account_store(cases: &[Value], seeds: &mut Seeds) {
    for case in cases {
        match call_of(case) {
            "storeOpen" => {
                let mode = 0u8;
                let (Some(key), Some(id), Some(value)) = (
                    hex_of(case, "accountKeyHex"),
                    hex_of(case, "idHex"),
                    hex_of(case, "valueHex"),
                ) else {
                    continue;
                };
                add(
                    seeds,
                    "account_store_open",
                    cat(&[&[mode, key.len() as u8, id.len() as u8], &key, &id, &value]),
                );
                if let (Some(plaintext), 32, 16, true) = (
                    hex_of(case, "expect.plaintextHex"),
                    key.len(),
                    id.len(),
                    value.len() > 13,
                ) {
                    add(
                        seeds,
                        "account_store_open",
                        cat(&[&[mode | 2], &key, &id, &value[1..13], &[0, 0], &plaintext]),
                    );
                }
            }
            "boxOpen" => {
                let (Some(recipient), Some(approver), Some(device_id), Some(sealed)) = (
                    hex_of(case, "recipientSeedHex"),
                    hex_of(case, "approverKeyHex"),
                    str_of(case, "deviceId"),
                    hex_of(case, "boxHex"),
                ) else {
                    continue;
                };
                add(
                    seeds,
                    "account_key_box_open",
                    cat(&[
                        &[0],
                        &recipient,
                        &approver,
                        &[device_id.len() as u8],
                        device_id.as_bytes(),
                        &sealed,
                    ]),
                );
            }
            _ => {}
        }
    }
    add(
        seeds,
        "account_key_box_open",
        cat(&[
            &[1],
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 32],
            &[0x44; 12],
            &[0xa1; 32],
            &[0, 0],
            b"device-ada-laptop",
        ]),
    );
}

fn field(bytes: &[u8]) -> Vec<u8> {
    cat(&[&[bytes.len() as u8], bytes])
}

fn device_link(cases: &[Value], seeds: &mut Seeds) {
    for case in cases {
        let device_id = str_of(case, "deviceId").unwrap_or("").as_bytes();
        match call_of(case) {
            "qr" | "qrMatches" => {
                let Some(key) = hex_of(case, "signingKeyHex") else {
                    continue;
                };
                let scanned = str_of(case, "scanned")
                    .or_else(|| str_of(case, "expect.qr"))
                    .unwrap_or("");
                add(
                    seeds,
                    "device_link",
                    cat(&[
                        &[0],
                        &key,
                        &[device_id.len() as u8],
                        device_id,
                        scanned.as_bytes(),
                    ]),
                );
            }
            "number" => {
                let fields: Option<Vec<Vec<u8>>> = [
                    "newDeviceKeyHex",
                    "approverKeyHex",
                    "commitmentHex",
                    "deviceNonceHex",
                    "approverNonceHex",
                ]
                .iter()
                .map(|path| hex_of(case, path))
                .collect();
                if let Some(fields) = fields {
                    add(seeds, "device_link", cat(&[&[1], &fields.concat()]));
                }
            }
            "waiterStep" => {
                let mut input = vec![2];
                input.extend(field(
                    str_of(case, "boundApproverDeviceId")
                        .unwrap_or("")
                        .as_bytes(),
                ));
                input.extend(field(
                    &hex_of(case, "boundApproverKeyHex").unwrap_or_default(),
                ));
                input.extend(field(
                    &hex_of(case, "boundCommitmentHex").unwrap_or_default(),
                ));
                input.extend(field(
                    str_of(case, "approverDeviceId").unwrap_or("").as_bytes(),
                ));
                input.extend(field(&hex_of(case, "approverKeyHex").unwrap_or_default()));
                input.extend(field(&hex_of(case, "commitmentHex").unwrap_or_default()));
                add(seeds, "device_link", input);
            }
            "sign" => {
                let (Some(seed), Some(key)) =
                    (hex_of(case, "seedHex"), hex_of(case, "signingKeyHex"))
                else {
                    continue;
                };
                let signature = hex_of(case, "expect.signatureHex").unwrap_or_else(|| vec![0; 64]);
                add(
                    seeds,
                    "device_link",
                    cat(&[&[3], &seed, &key, &signature, device_id]),
                );
            }
            _ => {}
        }
    }
}

fn group_meta(cases: &[Value], seeds: &mut Seeds) -> Result<(), Box<dyn std::error::Error>> {
    let empty = Extensions::<GroupContext>::default();
    let mut previous: Option<Vec<u8>> = None;
    for case in cases {
        let Some(wire) = str_of(case, "wire") else {
            continue;
        };
        add(seeds, "group_meta", cat(&[&[0, 0], wire.as_bytes()]));
        // The same value as a rename of a group that already has a name.
        if let Some(current) = &previous {
            add(
                seeds,
                "group_meta",
                cat(&[
                    &(current.len() as u16).to_be_bytes(),
                    current,
                    wire.as_bytes(),
                ]),
            );
        }
        if let Ok(named) = group_context_extensions_with_meta(&empty, wire.as_bytes()) {
            previous = Some(named.tls_serialize_detached()?);
        }
    }
    Ok(())
}

/// `content_hint_peek`: each fate's hint as authenticated data (mode 0), and
/// as a real application message a one-member group sealed with it (mode 1),
/// so the peek starts from bytes that parse.
fn content_hint(fixture: &Value, seeds: &mut Seeds) -> Result<(), Box<dyn std::error::Error>> {
    const NOW: i64 = 1_789_516_800;
    const GROUP: &[u8] = b"fuzz-seed-content-hint";
    let issuer = TestIssuer::from_seed(&[7u8; 32]);
    let mut seed = [0u8; 32];
    seed[0] = 1;
    let (_, public) = device_key_pair(&seed);
    let token = issuer.issue(
        "actor-ada",
        "device-ada",
        &public,
        NOW - 3_600,
        NOW + 86_400,
    )?;
    // A device holds its account's key, and refuses a credential certified
    // under any other (or certified at all, while it holds none).
    let held = account_identity_public_key(&TestIssuer::test_account_key("actor-ada"))?;
    let mut config = ClientConfig::new(token, seed, issuer.trusted_keys()?)
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(held));
    config.clock = Some(Box::new(FixedClock(NOW)));
    let mut client = Client::new(config)?;
    client.create_group(GROUP)?;
    for fate in fixture["fates"].as_array().into_iter().flatten() {
        match fate["hint"].as_u64().and_then(|h| u8::try_from(h).ok()) {
            Some(hint) => {
                add(seeds, "content_hint_peek", cat(&[&[0], &hint_aad(hint)]));
                if let Ok(sealed) = client.encrypt_with_hint(GROUP, b"seed", hint) {
                    add(seeds, "content_hint_peek", cat(&[&[1], &sealed]));
                }
            }
            // No hint, or one this build does not know.
            None => add(seeds, "content_hint_peek", vec![0, 0x70, 0x01, 0xff]),
        }
    }
    let plain = client.encrypt(GROUP, b"seed")?;
    add(seeds, "content_hint_peek", cat(&[&[1], &plain]));
    Ok(())
}

/// `welcome_frame`: every case's bytes as a join reads them (mode 0), and
/// every Welcome the fixture frames, framed again by the target (mode 1).
fn welcome_frame(cases: &[Value], seeds: &mut Seeds) {
    for case in cases {
        for path in ["bytesHex", "expect.framedHex"] {
            if let Some(bytes) = hex_of(case, path) {
                add(seeds, "welcome_frame", cat(&[&[0], &bytes]));
            }
        }
        if let Some(welcome) = hex_of(case, "welcomeHex") {
            add(seeds, "welcome_frame", cat(&[&[16], &welcome]));
        }
    }
    // Found by the target (core/tests/welcome_frame_fuzz_regressions.rs): a
    // version 2 magic cut inside its length.
    add(
        seeds,
        "welcome_frame",
        vec![0, 0xff, 0x50, 0x57, 0x02, 0x00, 0x80, 0x00, 0x3d],
    );
}

/// The targets that drive a real group (`mls_message_process`,
/// `welcome_join`, `key_package_check`) build their own message, Welcome and
/// key package; their seeds are the layouts that reach them: the real object
/// unchanged (an empty mask) and with one bit flipped. `call_grant_payload`
/// gets a grant's plaintext as `open_call_media_grant` reads it.
fn live_objects(seeds: &mut Seeds) -> Result<(), Box<dyn std::error::Error>> {
    use peachy_mls_core::call::{encode_media_grant_payload, MediaGrantPayload};

    add(seeds, "mls_message_process", cat(&[&[2], b"hello"]));
    add(seeds, "mls_message_process", vec![3, 0, 0]);
    add(seeds, "mls_message_process", vec![3, 0, 40, 1]);
    add(seeds, "welcome_join", vec![1, 0, 0]);
    add(seeds, "welcome_join", vec![1, 0, 60, 1]);
    add(seeds, "key_package_check", vec![1, 0, 0]);
    add(seeds, "key_package_check", vec![1, 0, 50, 1]);
    for tracks in [0usize, 1, 3] {
        let payload = MediaGrantPayload {
            generation: 7,
            secret: [9; 32].into(),
            session_id: "session-1".into(),
            track_names: (0..tracks).map(|n| format!("track-{n}")).collect(),
        };
        add(
            seeds,
            "call_grant_payload",
            encode_media_grant_payload(&payload)?,
        );
    }
    Ok(())
}

fn leaf_of(case: &Value, path: &str) -> Option<[u8; 4]> {
    let leaf = case.get(path)?;
    let leaf = leaf
        .as_u64()
        .or_else(|| leaf.as_str().and_then(|s| s.parse().ok()))?;
    Some(u32::try_from(leaf).ok()?.to_be_bytes())
}

/// A number the fixture writes as a JSON number or as a string.
fn num_of(case: &Value, path: &str) -> Option<i64> {
    int_of(case, path).or_else(|| str_of(case, path)?.parse().ok())
}

/// `call_grant_sealed`'s payload layout: `generation (4, BE) ‖ secret (32) ‖
/// session id ‖ 0x00 ‖ track ‖ 0x00 ‖ track …`.
fn grant_body(expect: &Value) -> Option<Vec<u8>> {
    let generation = u32::try_from(expect.get("generation")?.as_u64()?).ok()?;
    let mut body = generation.to_be_bytes().to_vec();
    body.extend(hex_of(expect, "secretHex")?);
    body.extend(str_of(expect, "sessionId")?.as_bytes());
    for track in expect.get("trackNames")?.as_array()? {
        body.push(0);
        body.extend(track.as_str()?.as_bytes());
    }
    Some(body)
}

/// `call_grant_open`: every `openMediaGrant` case as it arrives, to the key
/// its `ikmHex` derives (bit 1 for the other participant's), and with `enc`'s
/// length spelled out (bit 7). `call_grant_sealed`: each payload the fixture
/// opens to, sealed by the target under both suites, unchanged and with each
/// field changed, and its plaintext as the raw mode seals it.
fn media_grants(cases: &[Value], seeds: &mut Seeds) {
    use peachy_mls_core::call::{encode_media_grant_payload, MediaGrantPayload};

    const RECIPIENT_IKM: &str = "2b292e8e7266d27b3ba210343c0ff9eaa47303285ff22fb7e283c060e7018201";
    for case in cases.iter().filter(|c| call_of(c) == "openMediaGrant") {
        let (Some(call_id), Some(sender), Some(to), Some(enc), Some(ciphertext)) = (
            hex_of(case, "callIdHex"),
            leaf_of(case, "senderLeaf"),
            leaf_of(case, "toLeaf"),
            hex_of(case, "encHex"),
            hex_of(case, "ciphertextHex"),
        ) else {
            continue;
        };
        let other = u8::from(str_of(case, "ikmHex") != Some(RECIPIENT_IKM)) << 1;
        let header = cat(&[&call_id, &sender, &to]);
        add(
            seeds,
            "call_grant_open",
            cat(&[&[other], &header, &enc, &ciphertext]),
        );
        add(
            seeds,
            "call_grant_open",
            cat(&[
                &[other | 0x80],
                &header,
                &[enc.len() as u8],
                &enc,
                &ciphertext,
            ]),
        );
        let Some(expect) = case.get("expect").filter(|e| e.is_object()) else {
            continue;
        };
        let Some(body) = grant_body(expect) else {
            continue;
        };
        for suite in [0u8, 1] {
            for changed in 0u8..8 {
                let spec: &[u8] = if changed == 0 { &[] } else { &[0, 0, 1] };
                add(
                    seeds,
                    "call_grant_sealed",
                    cat(&[
                        &[suite | changed << 2],
                        &header,
                        &[spec.len() as u8],
                        spec,
                        &body,
                    ]),
                );
            }
        }
        let payload = MediaGrantPayload {
            generation: expect["generation"].as_u64().unwrap_or(0) as u32,
            secret: seed32(expect, "secretHex").unwrap_or([0; 32]).into(),
            session_id: str_of(expect, "sessionId").unwrap_or("").into(),
            track_names: expect["trackNames"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|t| t.as_str().map(String::from))
                .collect(),
        };
        if let Ok(plaintext) = encode_media_grant_payload(&payload) {
            for suite in [0u8, 1] {
                add(
                    seeds,
                    "call_grant_sealed",
                    cat(&[&[2 | suite], &header, &[0], &plaintext]),
                );
            }
        }
    }
}

/// `typing_open`: each fixture frame whole (mode 0), each wire sealed by the
/// group (mode 1) and read alone (mode 3), and the signed frames the member
/// makes for itself, another actor and another epoch (mode 2).
fn typing_frames(fixture: &Value, seeds: &mut Seeds) {
    let cases = ["cases", "signedCases"]
        .iter()
        .filter_map(|key| fixture[key].as_array())
        .flatten();
    for case in cases {
        if let Some(frame) = hex_of(case, "frame") {
            add(seeds, "typing_open", cat(&[&[0], &frame]));
        }
        if let Some(wire) = str_of(case, "wire") {
            add(seeds, "typing_open", cat(&[&[1], wire.as_bytes()]));
            add(seeds, "typing_open", cat(&[&[3], wire.as_bytes()]));
        }
    }
    for (typing, actor, delta) in [(1, 0, 0), (0, 0, 0), (1, 1, 0), (1, 0, 1)] {
        add(seeds, "typing_open", vec![2, typing, actor, delta]);
    }
    add(seeds, "typing_open", vec![2, 1, 0, 0, 0, 5, 1]);
}

/// `epoch_envelope`: each version 3 envelope under each secret the fixture
/// names with it (clear), and each version 3 seal's kind and inner bytes,
/// sealed by the target unchanged and with one bit flipped (set).
fn epoch_envelopes(cases: &[Value], seeds: &mut Seeds) {
    for case in cases {
        let envelope = hex_of(case, "envelopeHex").or_else(|| hex_of(case, "expect.envelopeHex"));
        let mut secrets: Vec<Vec<u8>> = hex_of(case, "epochSecretHex").into_iter().collect();
        for secret in case["epochSecretsHex"].as_array().into_iter().flatten() {
            if let Some(secret) = secret.as_str().and_then(|s| hex::decode(s).ok()) {
                secrets.push(secret);
            }
        }
        if let Some(envelope) = &envelope {
            for secret in secrets.iter().filter(|s| s.len() == 32) {
                add(seeds, "epoch_envelope", cat(&[&[0], secret, envelope]));
            }
        }
        let (Some(kind), Some(inner), true) = (
            num_of(case, "envelopeKind"),
            hex_of(case, "innerHex"),
            case.get("epochSecretHex").is_some(),
        ) else {
            continue;
        };
        add(seeds, "epoch_envelope", cat(&[&[1, kind as u8, 0], &inner]));
        add(
            seeds,
            "epoch_envelope",
            cat(&[&[1, kind as u8, 3, 0, 20, 1], &inner]),
        );
    }
}

/// `device_seal_open`: each `open` case as it arrives (clear), and each
/// `seal` case's group, secret, ephemeral and envelope sealed by the target
/// between the fixture's devices, with each change (set).
fn device_seals(cases: &[Value], seeds: &mut Seeds) {
    for case in cases {
        match call_of(case) {
            "open" => {
                if let (Some(seed), Some(seal), Some(envelope)) = (
                    hex_of(case, "recipientSeedHex"),
                    hex_of(case, "sealHex"),
                    hex_of(case, "envelopeHex"),
                ) {
                    add(
                        seeds,
                        "device_seal_open",
                        cat(&[&[0], &seed, &seal, &envelope]),
                    );
                }
            }
            "seal" => {
                let (Some(sender), Some(group), Some(secret), Some(ephemeral), Some(envelope)) = (
                    hex_of(case, "senderSeedHex"),
                    hex_of(case, "groupIdHex"),
                    hex_of(case, "epochSecretHex"),
                    hex_of(case, "ephemeralHex"),
                    hex_of(case, "envelopeHex"),
                ) else {
                    continue;
                };
                // Bo, the fixture's recipient, is the device seeded 0x22.
                let header = [1, sender[0], 0x22, group.len() as u8];
                for changed in 0u8..4 {
                    let spec: &[u8] = if matches!(changed, 1 | 2) {
                        &[0, 9, 1]
                    } else {
                        &[]
                    };
                    add(
                        seeds,
                        "device_seal_open",
                        cat(&[
                            &header,
                            &[changed, spec.len() as u8],
                            spec,
                            &group,
                            &secret,
                            &ephemeral,
                            &envelope,
                        ]),
                    );
                }
            }
            _ => {}
        }
    }
}

/// `commit_entry`: each entry the fixtures split, verify or build (clear),
/// and each `carry` and `wrap_veto` case's proposals and commit, carried by
/// the target, bare and under a veto (set).
fn commit_entries(carried: &[Value], steward: &[Value], seeds: &mut Seeds) {
    for case in carried.iter().chain(steward) {
        for path in ["bytesHex", "expect.bytesHex"] {
            if let Some(bytes) = hex_of(case, path) {
                add(seeds, "commit_entry", cat(&[&[0], &bytes]));
            }
        }
        if !matches!(call_of(case), "carry" | "wrap_veto") {
            continue;
        }
        let proposals: Vec<Vec<u8>> = case["proposalsHex"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| p.as_str().and_then(|s| hex::decode(s).ok()))
            .collect();
        let Some(commit) = hex_of(case, "commitHex").or_else(|| hex_of(case, "innerHex")) else {
            continue;
        };
        if proposals.len() > 255 || proposals.iter().any(|p| p.len() > 255) {
            continue;
        }
        for veto in [0u8, 1] {
            let mut input = vec![1, veto, proposals.len() as u8];
            for proposal in &proposals {
                input.extend(field(proposal));
            }
            input.extend(&commit);
            add(seeds, "commit_entry", input);
        }
    }
}

/// `steward_frames`: the fixture's sealed stamp and log copy (mode 0), what
/// they seal, sealed again by the target (mode 1), each repair notice's wire
/// (mode 2) and each meta (mode 3).
fn steward_frames(cases: &[Value], seeds: &mut Seeds) {
    for case in cases {
        let epoch = num_of(case, "epoch").map(|e| (e as u64).to_be_bytes());
        match (call_of(case), epoch) {
            ("open_stamp", Some(epoch)) => {
                if let Some(stamp) = hex_of(case, "stampHex") {
                    add(seeds, "steward_frames", cat(&[&[0], &epoch, &stamp]));
                }
            }
            ("open_log_copy", Some(epoch)) => {
                if let Some(copy) = hex_of(case, "copyHex") {
                    add(seeds, "steward_frames", cat(&[&[0], &epoch, &copy]));
                }
            }
            ("seal_stamp", Some(epoch)) => {
                let (Some(next), Some(steward), Some(mac)) = (
                    hex_of(case, "nextVerifierHex"),
                    hex_of(case, "stewardPubHex"),
                    hex_of(case, "macHex"),
                ) else {
                    continue;
                };
                for spec in [&[][..], &[0, 30, 1]] {
                    add(
                        seeds,
                        "steward_frames",
                        cat(&[
                            &[1],
                            &epoch,
                            &[1, spec.len() as u8],
                            spec,
                            &next,
                            &steward,
                            &mac,
                        ]),
                    );
                }
            }
            ("seal_log_copy", Some(epoch)) => {
                if let Some(envelope) = hex_of(case, "envelopeHex") {
                    for spec in [&[][..], &[0, 30, 1]] {
                        add(
                            seeds,
                            "steward_frames",
                            cat(&[&[1], &epoch, &[0, spec.len() as u8], spec, &envelope]),
                        );
                    }
                }
            }
            ("repair_notice", _) => {
                if let Some(wire) = str_of(case, "wire") {
                    add(seeds, "steward_frames", cat(&[&[2], wire.as_bytes()]));
                }
            }
            ("meta_key", _) => {
                if let Some(meta) = str_of(case, "meta") {
                    let actor = b"actor-ada";
                    add(
                        seeds,
                        "steward_frames",
                        cat(&[&[3, actor.len() as u8], actor, meta.as_bytes()]),
                    );
                }
            }
            _ => {}
        }
    }
}

/// `welcome_gap_block`: each block the fixture seals or opens (mode 0), each
/// gap it seals, sealed by the target unchanged and changed (mode 1), and
/// that gap's plaintext as the raw mode seals it (mode 2).
fn gap_blocks(cases: &[Value], seeds: &mut Seeds) {
    for case in cases {
        for path in ["blockHex", "expect.blockHex"] {
            if let Some(block) = hex_of(case, path) {
                add(seeds, "welcome_gap_block", cat(&[&[0], &block]));
            }
        }
        let Some(gap) = case["gap"].as_array() else {
            continue;
        };
        let entries: Vec<u8> = gap
            .iter()
            .filter_map(|entry| {
                let epoch = num_of(entry, "epoch")? as u64;
                Some(cat(&[&epoch.to_be_bytes(), &hex_of(entry, "secretHex")?]))
            })
            .flatten()
            .collect();
        let count = gap.len() as u8;
        add(seeds, "welcome_gap_block", cat(&[&[1, count, 0], &entries]));
        add(
            seeds,
            "welcome_gap_block",
            cat(&[&[1, count, 3, 0, 40, 1], &entries]),
        );
        let nonce = hex_of(case, "nonceHex").unwrap_or_else(|| vec![0x60; 12]);
        add(
            seeds,
            "welcome_gap_block",
            cat(&[&[2], &nonce, &[count], &entries]),
        );
    }
}

/// `account_signatures`: each fixture certificate and revocation as it
/// arrives (clear), and the fixture's device keys signed by the target with a
/// test account's key, unchanged and with one bit flipped (set).
fn account_signatures(cases: &[Value], seeds: &mut Seeds) {
    let account_key = TestIssuer::test_account_key("actor-ada");
    for case in cases {
        if !matches!(
            call_of(case),
            "verifyAccountDevice" | "verifyDeviceRevocation"
        ) {
            continue;
        }
        let (Some(account), Some(device), Some(signature)) = (
            hex_of(case, "accountKeyHex"),
            hex_of(case, "signingKeyHex"),
            hex_of(case, "signatureHex"),
        ) else {
            continue;
        };
        if account.len() != 32 || device.len() != 32 {
            continue;
        }
        add(
            seeds,
            "account_signatures",
            cat(&[&[0], &account, &device, &signature]),
        );
        add(
            seeds,
            "account_signatures",
            cat(&[&[1], &account_key, &device]),
        );
        add(
            seeds,
            "account_signatures",
            cat(&[&[1], &account_key, &device, &[0, 70, 1]]),
        );
    }
}

/// `account_store_signed`: each signed note, transfer box and hybrid box the
/// fixture opens, as it arrives; and what each opens to, sealed again by the
/// target (the mode byte's bit 7), unchanged and with one bit flipped.
fn signed_account_store(cases: &[Value], seeds: &mut Seeds) {
    // `mode % 3` picks the door and bit 7 seals: 0x81 is the note door
    // sealed, 0x82 the transfer box's and 0x80 the hybrid box's.
    for case in cases {
        let device_id = str_of(case, "deviceId").unwrap_or("").as_bytes();
        match call_of(case) {
            "noteOpenSigned" => {
                let (Some(key), Some(id), Some(sender_key), Some(value)) = (
                    hex_of(case, "accountKeyHex"),
                    hex_of(case, "idHex"),
                    hex_of(case, "senderKeyHex"),
                    hex_of(case, "valueHex"),
                ) else {
                    continue;
                };
                let now = num_of(case, "nowMs").unwrap_or(0);
                add(
                    seeds,
                    "account_store_signed",
                    cat(&[
                        &[0],
                        &key,
                        &id,
                        &sender_key,
                        &now.to_be_bytes(),
                        &field(device_id),
                        &value,
                    ]),
                );
                if let Some(plaintext) = hex_of(case, "expect.plaintextHex") {
                    let issued_at = &now.to_be_bytes()[2..];
                    for spec in [&[][..], &[0, 20, 1]] {
                        add(
                            seeds,
                            "account_store_signed",
                            cat(&[
                                &[0x81],
                                &key,
                                &id,
                                issued_at,
                                &field(device_id),
                                &field(spec),
                                &plaintext,
                            ]),
                        );
                    }
                }
            }
            "transferKeyOpen" => {
                let (Some(seed), Some(sealed)) =
                    (hex_of(case, "recipientSeedHex"), hex_of(case, "boxHex"))
                else {
                    continue;
                };
                add(
                    seeds,
                    "account_store_signed",
                    cat(&[&[1], &seed, &field(device_id), &sealed]),
                );
                if let Some(key) = hex_of(case, "expect.transferKeyHex") {
                    for spec in [&[][..], &[0, 40, 1]] {
                        add(
                            seeds,
                            "account_store_signed",
                            cat(&[
                                &[0x82],
                                &seed,
                                &[0x44; 32],
                                &[0x0c; 12],
                                &key,
                                &field(spec),
                                device_id,
                            ]),
                        );
                    }
                }
            }
            "boxAcceptHybrid" => {
                let (Some(seed), Some(approver), Some(sealed)) = (
                    hex_of(case, "recipientSeedHex"),
                    hex_of(case, "approverKeyHex"),
                    hex_of(case, "boxHex"),
                ) else {
                    continue;
                };
                add(
                    seeds,
                    "account_store_signed",
                    cat(&[&[2], &seed, &approver, &field(device_id), &sealed]),
                );
                if let Some(account_key) = hex_of(case, "expect.accountKeyHex") {
                    for spec in [&[][..], &[0, 60, 1]] {
                        add(
                            seeds,
                            "account_store_signed",
                            cat(&[
                                &[0x80],
                                &[0x11; 32],
                                &seed,
                                &account_key,
                                &field(spec),
                                device_id,
                            ]),
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

/// `device_link_exchange`: each commitment and link-key signature the fixture
/// checks, laid out as it arrives, and each approver step's fields.
fn device_link_exchange(cases: &[Value], seeds: &mut Seeds) {
    const SEED: [u8; 32] = [0x11; 32];
    let signed = |case: &Value, paths: [&str; 4]| -> Option<Vec<u8>> {
        let fields: Vec<Vec<u8>> = paths
            .iter()
            .map(|path| hex_of(case, path))
            .collect::<Option<_>>()?;
        fields
            .iter()
            .map(Vec::len)
            .eq([32, 32, 32, 64])
            .then(|| fields.concat())
    };
    for case in cases {
        let device_id = str_of(case, "deviceId").unwrap_or("").as_bytes();
        match call_of(case) {
            "verifyCommitment" => {
                let paths = [
                    "approverKeyHex",
                    "signingKeyHex",
                    "commitmentHex",
                    "signatureHex",
                ];
                if let Some(fields) = signed(case, paths) {
                    add(
                        seeds,
                        "device_link_exchange",
                        cat(&[&[0], &SEED, &fields, device_id]),
                    );
                }
            }
            "verifyLinkKey" => {
                let paths = [
                    "signingKeyHex",
                    "commitmentHex",
                    "deviceNonceHex",
                    "signatureHex",
                ];
                if let Some(fields) = signed(case, paths) {
                    add(
                        seeds,
                        "device_link_exchange",
                        cat(&[&[1], &SEED, &fields, device_id]),
                    );
                }
            }
            "approverStep" => {
                let mut input = vec![2];
                for path in [
                    "pendingKeyHex",
                    "commitmentHex",
                    "boundDeviceNonceHex",
                    "listedKeyHex",
                    "listedCommitmentHex",
                    "listedDeviceNonceHex",
                    "listedApproverNonceHex",
                ] {
                    input.extend(field(&hex_of(case, path).unwrap_or_default()));
                }
                add(seeds, "device_link_exchange", input);
            }
            _ => {}
        }
    }
}

/// `server_key_list`: the production list as its server serves it, the test
/// issuer's, and shapes no server writes (mode 0); and built lists (mode 1):
/// the carried key alone, under another use, listed twice under two keys,
/// and beside keys no set carries.
fn server_key_lists(seeds: &mut Seeds) -> Result<(), Box<dyn std::error::Error>> {
    let carried = peachy_mls_core::TrustedServerKeys::pinned(
        peachy_mls_core::server_key_pins::PINNED_PRODUCTION,
    )?;
    let entries: Vec<Value> = carried
        .iter()
        .map(|(kid, raw)| {
            serde_json::json!({
                "kid": kid,
                "publicKey": base64::engine::general_purpose::STANDARD.encode(raw),
                "current": true,
                "use": "device",
            })
        })
        .collect();
    let production = serde_json::json!({ "enabled": true, "keys": entries }).to_string();
    let issuer = TestIssuer::from_seed(&[7u8; 32]);
    for json in [
        production,
        issuer.published_json(),
        issuer.published_json_with_use("notary"),
        format!("[{}]", serde_json::json!(entries)),
        "{}".to_owned(),
    ] {
        add(seeds, "server_key_list", cat(&[&[0], json.as_bytes()]));
    }
    for built in [
        vec![1, 0, 0, 0],
        vec![1, 0, 0, 1],
        vec![1, 0, 0, 0, 0, 1, 0],
        vec![1, 0, 1, 0, 0, 0, 0],
        vec![1, 1, 2, 0, 2, 3, 2, 3, 4, 3],
    ] {
        add(seeds, "server_key_list", built);
    }
    Ok(())
}

/// `own_devices`: each door with every field real (`mode / 6` all ones),
/// and with a byte of a real field changed; and the device-list JSON a
/// client hands the core, among it a list naming the tablet twice and
/// arrays where an object goes.
fn own_device_lists(seeds: &mut Seeds) -> Result<(), Box<dyn std::error::Error>> {
    const NOW: i64 = 1_789_516_800;
    let mut phone_seed = [0u8; 32];
    phone_seed[0] = 1;
    let mut tablet_seed = [0u8; 32];
    tablet_seed[0] = 5;
    let tablet = device_key_pair(&tablet_seed).1;
    let approval =
        peachy_mls_core::sign_device_approval(&phone_seed, "device-ada-tablet", &tablet)?;
    let row = |key: &[u8; 32], vouched: bool| {
        let mut row = serde_json::json!({
            "id": "device-ada-tablet",
            "twinOf": "tablet-plain",
            "signingKey": hex::encode(key),
        });
        if vouched {
            row["approvedByDeviceId"] = "device-ada".into();
            row["approvalSignature"] = hex::encode(approval).into();
        }
        row
    };
    let stranger = device_key_pair(&[0x99; 32]).1;
    // The seat check (42), the row check (91) and the standing (92, and 86
    // with the tablet not approved first), every field real.
    add(seeds, "own_devices", vec![42, 0, 0]);
    add(seeds, "own_devices", vec![42, 3, 0, 30, 1, 0]);
    add(seeds, "own_devices", vec![42, 0, 0, 0, 5, 1]);
    add(seeds, "own_devices", vec![91, 0, 0, 0]);
    add(seeds, "own_devices", vec![91, 0, 0, 0, 0, 7, 1]);
    add(seeds, "own_devices", vec![92, 0, 0]);
    add(seeds, "own_devices", vec![86, 0, 0]);
    let plain = serde_json::json!({ "id": "tablet-plain" });
    let lists = [
        (3, serde_json::json!([plain, row(&tablet, false)])),
        (
            4,
            serde_json::json!({ "restoredSince": NOW, "keys": [hex::encode(tablet)] }),
        ),
        (
            5,
            serde_json::json!({
                "named": "device-ada-tablet",
                "ownDeviceIds": ["device-ada"],
                "rows": [row(&tablet, true)],
            }),
        ),
        (
            11,
            serde_json::json!({
                "named": "device-ada-tablet",
                "ownDeviceIds": ["device-ada"],
                "rows": [row(&tablet, false), row(&stranger, false)],
            }),
        ),
        (
            5,
            serde_json::json!({
                "ownDeviceIds": ["device-ada"],
                "restoredSince": NOW,
                "rows": [row(&tablet, true)],
            }),
        ),
        // Arrays where an object goes: a row, a restore's answer and a
        // revocation request each written as a list of their fields' values.
        // Read field by field, an array would answer as an object does.
        (
            3,
            serde_json::json!([
                plain,
                ["device-ada-tablet", "tablet-plain", hex::encode(tablet)]
            ]),
        ),
        (4, serde_json::json!([NOW, [hex::encode(tablet)]])),
        (
            5,
            serde_json::json!(["device-ada-tablet", ["device-ada"], [row(&tablet, true)]]),
        ),
        (
            5,
            serde_json::json!({
                "named": "device-ada-tablet",
                "ownDeviceIds": ["device-ada"],
                "rows": [[
                    "device-ada-tablet",
                    "tablet-plain",
                    hex::encode(tablet),
                    "device-ada",
                    hex::encode(approval)
                ]],
            }),
        ),
    ];
    for (mode, json) in lists {
        add(
            seeds,
            "own_devices",
            cat(&[&[mode], json.to_string().as_bytes()]),
        );
    }
    Ok(())
}

/// `content_hint_peek`'s resend readers: authenticated data carrying a
/// commitment (mode 0), and the plaintexts that carry a resend secret
/// (mode 2).
fn resend_secrets(seeds: &mut Seeds) {
    use peachy_mls_core::hint::{
        hint_aad_with_commitment, CONTENT_HINT_RESENDABLE, CONTENT_HINT_RESENDABLE_LANE,
    };
    for hint in [CONTENT_HINT_RESENDABLE, CONTENT_HINT_RESENDABLE_LANE] {
        add(
            seeds,
            "content_hint_peek",
            cat(&[&[0], &hint_aad_with_commitment(hint, Some([7; 16]))]),
        );
    }
    let frame = br#"{"i":"3F1C2B8E-7A41-4D2C-9B1E-000000000001","t":"hi"}"#;
    add(
        seeds,
        "content_hint_peek",
        cat(&[&[2, CONTENT_HINT_RESENDABLE, 0xFF, 1], frame]),
    );
    let lane = br#"{"z":"AAAAAAAAAAAAAAAAAAAAAA==","d":"x"}"#;
    add(
        seeds,
        "content_hint_peek",
        cat(&[&[2, CONTENT_HINT_RESENDABLE_LANE], lane]),
    );
}
