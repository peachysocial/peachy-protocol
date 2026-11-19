// SPDX-License-Identifier: MIT
//! The binding's own tests, run under Node by `wasm-pack test --node`.
//!
//! Rust-side on purpose: these hold the *binding*, not the protocol — that the
//! JS types are the ones the doc promises, that a structured result carries the
//! keys it says it does, and that a core error arrives as an exception whose
//! message is the core's own `Display`. The protocol itself is already held by
//! `mls/core/tests/end_to_end.rs`; repeating it here would only prove that
//! calling the same function twice gives the same answer.
//!
//! `mls/wasm/tests/node/journey.test.mjs` is the other half: the same journey
//! driven from JavaScript through the built package, which is the only thing
//! that can catch glue that compiles and then hands JS an object nobody can
//! read.
//!
//! The whole file is `wasm32`-only. On the host there is no JS engine to hold a
//! `Uint8Array`, so `cargo test --workspace` compiles this to nothing rather
//! than to a test that would fail for a reason unrelated to the code.
#![cfg(target_arch = "wasm32")]

use serde::Deserialize;
use wasm_bindgen::{JsError, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

use peachy_mls_wasm::{
    account_identity_public_key, generate_signing_key_seed, sign_device_approval,
    signing_key_public_key, verify_device_approval, MlsClient, TestIssuer,
};

// ---- Harness ----------------------------------------------------------------

/// The message a thrown `JsError` carries. `JsError` is write-only in Rust —
/// it exists to become an exception — so getting the text back means going
/// through `JsValue` and reading the `Error`'s `message`.
fn message<T>(result: Result<T, JsError>) -> String {
    match result {
        Ok(_) => "<no error>".to_string(),
        Err(err) => {
            let value: JsValue = err.into();
            String::from(js_sys::Error::from(value).message())
        }
    }
}

fn ok<T>(result: Result<T, JsError>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => {
            let value: JsValue = err.into();
            let text = String::from(js_sys::Error::from(value).message());
            panic!("expected success, got: {text}")
        }
    }
}

/// An hour before now, on the wall clock the binding itself reads. This was a
/// fixed date with a year-long credential; a credential may no longer claim
/// more than the issuer's thirty-one days (`MAX_CREDENTIAL_LIFETIME_SECONDS`
/// in mls/core/src/identity.rs), and a fixed date with a real lifetime is a
/// test that starts failing a month after it was written.
fn now() -> f64 {
    (js_sys::Date::now() / 1000.0).floor() - 3_600.0
}
const LIFETIME: f64 = 2_592_000.0;

fn issuer() -> TestIssuer {
    ok(TestIssuer::new(&[7u8; 32]))
}

/// The account identity key a client opened on an `issue` credential for
/// `actor` must say it holds: the issuer certifies under a stand-in key.
fn held_key(actor: &str) -> Vec<u8> {
    ok(account_identity_public_key(
        peachy_mls_core::issuer::TestIssuer::test_account_key(actor).to_vec(),
    ))
}

/// A device: a seed, a credential minted for it, and the identity key it holds.
struct Device {
    seed: Vec<u8>,
    token: String,
    held: Vec<u8>,
}

fn device(issuer: &TestIssuer, actor: &str, device_id: &str, seed_byte: u8) -> Device {
    let seed = vec![seed_byte; 32];
    let public = ok(signing_key_public_key(seed.clone()));
    let now = now();
    let token = ok(issuer.issue(actor, device_id, &public, now, now + LIFETIME));
    Device {
        seed,
        token,
        held: held_key(actor),
    }
}

fn client(issuer: &TestIssuer, device: &Device) -> MlsClient {
    ok(MlsClient::new(
        &issuer.published_json(),
        &device.token,
        device.seed.clone(),
        Some(device.held.clone()),
    ))
}

// ---- What crosses -----------------------------------------------------------
//
// Deserialized as plain structs rather than as the crate's own DTOs: the DTOs
// are serialize-only and private, and a test that shares a type with the code
// under test cannot notice that the type is wrong.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityOut {
    actor_id: String,
    device_id: String,
    device_key: serde_bytes::ByteBuf,
    kid: String,
    expires_at: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitBundleOut {
    commit: serde_bytes::ByteBuf,
    welcome: Option<serde_bytes::ByteBuf>,
    epoch: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IncomingOut {
    kind: String,
    #[serde(default)]
    plaintext: Option<serde_bytes::ByteBuf>,
    #[serde(default)]
    sender: Option<IdentityOut>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RosterEntryOut {
    leaf_index: u32,
    leaf_key: serde_bytes::ByteBuf,
    identity: Option<IdentityOut>,
    rejection: Option<RejectionOut>,
}

/// Not read by any assertion here — every leaf in these groups verifies, and a
/// leaf whose credential expires mid-session needs a clock these tests cannot
/// move. It is still typed rather than skipped: if a rejection ever does arrive
/// with a different shape, the roster parse fails instead of quietly accepting
/// it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct RejectionOut {
    code: u32,
    name: String,
}

/// Takes anything that becomes a `JsValue` — the typed results
/// (`MlsCommitBundleJs` and friends) are imported TypeScript types on the Rust
/// side, so they have to go back through `JsValue` to be read at all.
fn from_js<T: serde::de::DeserializeOwned>(value: impl Into<JsValue>) -> T {
    match serde_wasm_bindgen::from_value(value.into()) {
        Ok(parsed) => parsed,
        Err(err) => panic!("the result object did not have the shape it promises: {err}"),
    }
}

// ---- Tests ------------------------------------------------------------------

/// Two members, the whole way round: create, key package, add, Welcome, a
/// message each way, the roster, an exported secret both agree on, and the
/// removed member left unable to read what comes next.
#[wasm_bindgen_test]
fn two_member_journey() {
    let issuer = issuer();
    let ada = device(&issuer, "actor-ada", "device-ada", 1);
    let bo = device(&issuer, "actor-bo", "device-bo", 2);
    let mut ada_client = client(&issuer, &ada);
    let mut bo_client = client(&issuer, &bo);

    let group = b"group-journey";
    ok(ada_client.create_group(group));
    assert_eq!(ok(ada_client.epoch(group)), 0.0);
    let ids: JsValue = ada_client.group_ids().into();
    assert_eq!(js_sys::Array::from(&ids).length(), 1);

    let key_package = ok(bo_client.generate_key_package());
    let bundle: CommitBundleOut = from_js(ok(ada_client.add_member(group, &key_package)));
    assert_eq!(bundle.epoch, 1.0, "adding a member moves the epoch on");
    let welcome = match bundle.welcome {
        Some(welcome) => welcome,
        None => panic!("an add must carry a Welcome"),
    };
    assert!(!bundle.commit.is_empty());

    // Staged, not adopted. A real caller merges only once the delivery service
    // has accepted the commit; there is no delivery service here, so this line
    // is standing in for its yes.
    assert!(ok(ada_client.has_pending_commit(group)));
    assert_eq!(ok(ada_client.epoch(group)), 0.0, "not until it merges");
    assert_eq!(ok(ada_client.merge_pending_commit(group)), 1.0);
    assert!(!ok(ada_client.has_pending_commit(group)));

    let joined = ok(bo_client.join_from_welcome(&welcome));
    assert_eq!(joined, group.to_vec(), "the joined group id comes back");

    // Ada speaks, Bo reads.
    let ciphertext = ok(ada_client.encrypt(group, b"hello from ada".to_vec()));
    let incoming: IncomingOut = from_js(ok(bo_client.process_message(group, &ciphertext, None)));
    assert_eq!(incoming.kind, "application");
    assert_eq!(
        incoming.plaintext.map(|bytes| bytes.into_vec()),
        Some(b"hello from ada".to_vec())
    );
    let sender = match incoming.sender {
        Some(sender) => sender,
        None => panic!("an application message names its sender"),
    };
    assert_eq!(sender.actor_id, "actor-ada");
    assert_eq!(sender.device_id, "device-ada");
    assert_eq!(sender.device_key.len(), 32);
    assert_eq!(sender.kid, issuer.kid());
    // Minted a moment ago against the wall clock, so within a few seconds of
    // an hour short of thirty days from now.
    assert!((sender.expires_at - (now() + LIFETIME)).abs() <= 5.0);

    // Bo speaks, Ada reads.
    let ciphertext = ok(bo_client.encrypt(group, b"hello from bo".to_vec()));
    let incoming: IncomingOut = from_js(ok(ada_client.process_message(group, &ciphertext, None)));
    assert_eq!(incoming.kind, "application");

    // The roster, both entries verified.
    let roster: Vec<RosterEntryOut> = from_js(ok(ada_client.roster(group)));
    assert_eq!(roster.len(), 2);
    let mut actors: Vec<String> = roster
        .iter()
        .map(|entry| match &entry.identity {
            Some(identity) => identity.actor_id.clone(),
            None => panic!("every leaf in this group verifies"),
        })
        .collect();
    actors.sort();
    assert_eq!(actors, vec!["actor-ada", "actor-bo"]);
    assert!(roster.iter().all(|entry| entry.rejection.is_none()));
    assert_eq!(roster.iter().map(|entry| entry.leaf_index).sum::<u32>(), 1);

    // A seated leaf carries its own signing key, and it is Bo's real one — the
    // same 32 bytes `peachy_mls_group_member`'s `out_device_key` hands the
    // other three bindings (`mls/cabi/tests/abi.rs` asserts that side). This is
    // the key Bo's own devices check a device approval against before they
    // seat a SECOND device of Bo's (`checkOwnDeviceApproval`): it has to come
    // out of the tree, because a key taken from the directory that served the
    // approval is a key the directory got to choose.
    let bos_leaf = match roster
        .iter()
        .find(|entry| entry.identity.as_ref().map(|id| id.device_id.as_str()) == Some("device-bo"))
    {
        Some(entry) => entry,
        None => panic!("bo is in this group"),
    };
    let bos_key = match &bos_leaf.identity {
        Some(identity) => identity.device_key.to_vec(),
        None => panic!("bo's credential verifies"),
    };
    assert_eq!(bos_key, ok(signing_key_public_key(bo.seed.clone())));
    // And it is usable as one: an approval over it verifies, against a key
    // nobody passed alongside it.
    let approver_seed = vec![0x2Bu8; 32];
    let approval = ok(sign_device_approval(
        approver_seed.clone(),
        "device-bo-second",
        &bos_key,
    ));
    assert!(verify_device_approval(
        &ok(signing_key_public_key(approver_seed.clone())),
        "device-bo-second",
        &bos_key,
        &approval,
    ));

    // The exporter: the same label and context, the same 32 bytes, on both.
    let ada_secret = ok(ada_client.export_secret(group, "peachy/test", b"ctx", 32));
    let bo_secret = ok(bo_client.export_secret(group, "peachy/test", b"ctx", 32));
    assert_eq!(ada_secret, bo_secret);
    let other_label = ok(ada_client.export_secret(group, "peachy/other", b"ctx", 32));
    assert_ne!(ada_secret, other_label);

    // Ada removes Bo. Bo learns it from the commit, and can no longer read.
    let leaf = ok(ada_client.leaf_of_device(group, "device-bo"));
    // The leaf key comes from the same roster entry as the index; for a
    // verified leaf it is the device key the credential binds.
    assert_eq!(bos_leaf.leaf_key.to_vec(), bos_key);
    let bundle: CommitBundleOut = from_js(ok(ada_client.remove_member(
        group,
        leaf,
        &bos_leaf.leaf_key,
    )));
    ok(ada_client.merge_pending_commit(group));
    let removal: IncomingOut = from_js(ok(bo_client.process_commit(group, &bundle.commit)));
    assert_eq!(removal.kind, "commit");
    assert!(!ok(bo_client.is_active(group)));

    let after = ok(ada_client.encrypt(group, b"just us now".to_vec()));
    assert_eq!(
        message(bo_client.process_message(group, &after, None)),
        "not an active member of this group",
        "a removed member's failure is named, not a decrypt error"
    );
}

/// GROUP RECOVERY ACROSS THE BINDING (docs/mls-core.md §Group recovery): a
/// copy one commit behind is refused a message sealed past it as a `stale
/// copy`, and the head read the driver asks for says to rejoin, as a string
/// step.
#[wasm_bindgen_test]
fn a_stale_copy_is_told_to_rejoin() {
    let issuer = issuer();
    let mut ada = client(&issuer, &device(&issuer, "actor-ada", "device-ada", 1));
    let mut bo = client(&issuer, &device(&issuer, "actor-bo", "device-bo", 2));
    let group = b"group-recovery";
    ok(ada.create_group(group));
    let key_package = ok(bo.generate_key_package());
    let bundle: CommitBundleOut = from_js(ok(ada.add_member(group, &key_package)));
    ok(ada.merge_pending_commit(group));
    let welcome = match bundle.welcome {
        Some(welcome) => welcome,
        None => panic!("an add carries a Welcome"),
    };
    ok(bo.join_from_welcome(&welcome));

    ok(ada.self_update(group));
    let head_epoch = ok(ada.merge_pending_commit(group));
    let sealed = ok(ada.encrypt(group, b"your turn".to_vec()));
    assert!(
        message(bo.process_message(group, &sealed, None)).starts_with("stale copy:"),
        "{}",
        message(bo.process_message(group, &sealed, None))
    );

    assert!(ok(bo.recovery_read_due(group, true, 1_000.0)));
    assert!(!ok(bo.recovery_read_due(group, true, 1_001.0)));
    let step: JsValue = ok(bo.recovery_begin(group)).into();
    assert_eq!(step.as_string().as_deref(), Some("read_head"));
    assert!(
        message(bo.recovery_judge(group, "sideways", None, None, true, 1_000.0))
            .contains("unknown head read kind")
    );
    let step: JsValue = ok(bo.recovery_judge(
        group,
        "sealed_ahead",
        Some(head_epoch),
        Some(vec![0u8; 32]),
        true,
        1_000.0,
    ))
    .into();
    assert_eq!(step.as_string().as_deref(), Some("rejoin_stuck"));
    let owed: JsValue = ok(bo.recovery_drain_complete(2_000.0, true, 2_000.0)).into();
    assert_eq!(js_sys::Array::from(&owed).length(), 0);
}

/// A credential minted for somebody else's key, replayed onto this device.
/// The one equality that makes a leaf credential mean anything.
#[wasm_bindgen_test]
fn a_credential_for_another_key_is_refused() {
    let issuer = issuer();
    let ada = device(&issuer, "actor-ada", "device-ada", 1);
    let other_seed = vec![9u8; 32];

    assert_eq!(
        message(MlsClient::new(
            &issuer.published_json(),
            &ada.token,
            other_seed.clone(),
            Some(ada.held.clone())
        )),
        "device credential rejected: leaf_key_mismatch"
    );
}

/// The three argument shapes a JS caller gets wrong first, each answered with a
/// sentence rather than a trap.
#[wasm_bindgen_test]
fn bad_arguments_are_named() {
    let issuer = issuer();
    let ada = device(&issuer, "actor-ada", "device-ada", 1);

    assert_eq!(
        message(MlsClient::new(
            &issuer.published_json(),
            &ada.token,
            vec![1, 2, 3],
            Some(ada.held.clone())
        )),
        "a device signing key seed must be exactly 32 bytes, got 3"
    );
    assert!(message(MlsClient::new(
        "not json at all",
        &ada.token,
        ada.seed.clone(),
        Some(ada.held.clone())
    ))
    .starts_with("invalid argument: published key list is not JSON"));
    assert_eq!(
        message(MlsClient::new(
            &issuer.published_json(),
            "pdc1.nonsense",
            ada.seed.clone(),
            Some(ada.held.clone())
        )),
        "device credential rejected: malformed"
    );

    let mut client = client(&issuer, &ada);
    assert_eq!(
        message(client.encrypt(b"no-such-group", b"hi".to_vec())),
        "no such group"
    );
    assert_eq!(message(client.epoch(b"no-such-group")), "no such group");
}

/// The enrollment pair: a seed from the platform CSPRNG — which is the one call
/// that proves `getrandom`'s wasm32 opt-in is wired — and the public key a
/// credential gets bound to.
#[wasm_bindgen_test]
fn a_generated_seed_enrolls() {
    let issuer = issuer();
    let seed = ok(generate_signing_key_seed());
    assert_eq!(seed.len(), 32);
    assert_ne!(seed, vec![0u8; 32], "a seed of zeroes is not randomness");
    assert_ne!(
        seed,
        ok(generate_signing_key_seed()),
        "two seeds in a row are not the same seed"
    );

    let public = ok(signing_key_public_key(seed.clone()));
    let now = now();
    let token = ok(issuer.issue("actor-new", "device-new", &public, now, now + LIFETIME));
    let client = ok(MlsClient::new(
        &issuer.published_json(),
        &token,
        seed.clone(),
        Some(held_key("actor-new")),
    ));
    let identity: IdentityOut = from_js(ok(client.identity()));
    assert_eq!(identity.actor_id, "actor-new");
    assert_eq!(identity.device_key.into_vec(), public);
}
