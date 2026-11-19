// SPDX-License-Identifier: MIT
//! The golden device-link fixture, replayed against the real implementation.
//!
//! `mls/fixtures/device-link.json` is a table of (inputs, expected verdict)
//! over the pure functions in `mls/core/src/device_link.rs`: the exact
//! bytes an approving device signs, the signature it produces, whether an
//! approval holds, the QR code a new device shows, and the commit-then-reveal
//! two-digit number both devices show a person. This
//! file is the Rust half of its replay;
//! `mls/wasm/tests/node/device-link.test.mjs` is the JavaScript half, through
//! the wasm binding, and Swift and Kotlin reach the same door across C.
//!
//! The third sibling of `rules_fixture.rs` and `credentials_fixture.rs`.
//! `rules.json` pins what the GROUP POLICY decides about a proposal,
//! `credentials.json` what the IDENTITY layer decides about a leaf, and this
//! one what four clients each compute for a person who is holding two devices
//! and comparing two screens.
//!
//! ## What this actually holds
//!
//! 1. **Every case's verdict is the implementation's verdict.** The obvious
//!    half.
//! 2. **Every case that expects a REFUSAL gets one**, with the sentence it
//!    names. A refusal is not a verdict, and the difference is the whole of why
//!    an `expectError` case exists: a signing key of the wrong length handed to
//!    `statement` is a caller mistake, and a replay that let it become
//!    `valid: false` would be blurring the one distinction this table is about.
//! 3. **All five calls are reached.** A call nothing exercises is a function
//!    three clients are not held to.
//! 4. **The number refuses a nonce that does not open its commitment, and one
//!    key against itself**, asserted
//!    here in Rust as well as in the file, so a fixture that round-trips its
//!    own mistakes still fails.
//! 5. **A key package's identity is read out of its own bytes.** The fifth
//!    call, `keyPackageIdentity`, is not one of the four pure functions — it is
//!    the other half of the same feature. An approval names a device id and a
//!    signing key, and this is where an adder gets those two values from
//!    without asking the server that served the package
//!    (docs/identity.md §What the adder checks).
//!
//! The fixture is read with `include_str!`, so a file that moves is a COMPILE
//! error and a JSON typo is a parse failure, rather than a test that quietly
//! finds zero cases and reports success.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use peachy_mls_core::device_link::{
    device_approval_statement, device_link_approver_number, device_link_commitment,
    device_link_number, device_link_qr, device_link_qr_matches, device_link_qr_secret,
    device_link_waiter_step, sign_device_approval, verify_device_approval, DeviceLinkWaiterStep,
    DEVICE_APPROVAL_DOMAIN, DEVICE_LINK_APPROVER_NUMBER_DOMAIN, DEVICE_LINK_COMMIT_DOMAIN,
    DEVICE_LINK_NUMBER_DOMAIN,
};
use peachy_mls_core::error::CredentialRejection;
use peachy_mls_core::fixture::{evaluate_case_json, FORMAT_VERSION};
use peachy_mls_core::group::{Client, ClientConfig};
use peachy_mls_core::identity::FixedClock;
use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::signing_key_public_key;
use serde_json::Value;

/// The account identity key a device of `actor` holds: the one
/// `TestIssuer::issue` certifies it under. A device holding no key refuses a
/// certified credential of its own.
fn held(actor: &str) -> [u8; 32] {
    peachy_mls_core::account_identity_public_key(&TestIssuer::test_account_key(actor))
        .expect("derive")
}

const FIXTURE: &str = include_str!("../../fixtures/device-link.json");

/// Every `call` the table has to reach, spelled out here rather than derived
/// from the file: a derivation from the same source cannot notice that a call
/// stopped being exercised.
const CALLS: [&str; 22] = [
    "statement",
    "sign",
    "verify",
    "commitment",
    "number",
    "approverNumber",
    "qr",
    "qrMatches",
    "accountIdentity",
    "signAccountDevice",
    "verifyAccountDevice",
    "signDeviceRevocation",
    "verifyDeviceRevocation",
    "installRevocationTargets",
    "keyPackageIdentity",
    "waiterStep",
    "signCommitment",
    "verifyCommitment",
    "approverStep",
    "linkKey",
    "signLinkKey",
    "verifyLinkKey",
];

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("mls/fixtures/device-link.json is valid JSON")
}

fn cases(root: &Value) -> &Vec<Value> {
    root["cases"].as_array().expect("`cases` is an array")
}

#[test]
fn the_fixture_declares_the_format_this_build_reads() {
    let root = fixture();
    assert_eq!(
        root["version"].as_u64(),
        Some(u64::from(FORMAT_VERSION)),
        "the fixture's format version and peachy_mls_core::fixture::FORMAT_VERSION disagree; \
         a case's SHAPE changed, which is not something to read past"
    );

    // A floor, under today's count on purpose, so growth never rewrites it and
    // a replay that stopped finding cases cannot read as a clean pass over
    // nothing — the failure this whole file exists to make impossible.
    assert!(
        cases(&root).len() >= 34,
        "only {} cases — the fixture shrank or stopped parsing",
        cases(&root).len()
    );

    // Every case says which table it belongs to. The door defaults an absent
    // `kind` to `rules`, which is what keeps `rules.json` working unchanged —
    // and which would silently send a device-link case to the policy layer.
    for case in cases(&root) {
        assert_eq!(
            case["kind"].as_str(),
            Some("device_link"),
            "case {} has no `kind`: \"device_link\"",
            case["id"]
        );
        // Exactly one of the two, never both and never neither: a case with an
        // `expect` AND an `expectError` would be read differently by the four
        // replays, and one with neither asserts nothing at all.
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
        assert!(
            ids.insert(id.clone()),
            "two cases share the id {id:?}; ids are how a failure is found again"
        );

        // The whole case object goes to the door, `expect`, `expectError` and
        // `why` included and ignored — the same call the wasm, Swift and
        // Kotlin replays make.
        let outcome = evaluate_case_json(&case.to_string());

        match case["expectError"].as_str() {
            Some(expected) => match outcome {
                Ok(verdict) => failures.push(format!(
                    "  {id}\n    expected a refusal naming {expected:?}\n    actual   {verdict}"
                )),
                Err(err) => {
                    let message = err.to_string();
                    if !message.contains(expected) {
                        failures.push(format!(
                            "  {id}\n    expected a refusal naming {expected:?}\n    \
                             actual   {message}"
                        ));
                    }
                }
            },
            None => match outcome {
                Err(err) => failures.push(format!(
                    "  {id}\n    expected {}\n    actual   refused: {err}",
                    case["expect"]
                )),
                Ok(verdict) => {
                    let actual: Value = serde_json::from_str(&verdict)
                        .expect("the door returns JSON it wrote itself");
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
        "{} of {} fixture cases disagree with mls/core/src/device_link.rs.\n\
         Either the derivation changed — in which case every client changed with it and \
         the fixture is the record of that — or the fixture is wrong. Note that a change \
         to either domain string changes every statement, signature and code in this file.\n{}",
        failures.len(),
        cases(&root).len(),
        failures.join("\n")
    );
}

#[test]
fn every_call_is_reached_by_some_case() {
    let root = fixture();
    let reached: BTreeSet<&str> = cases(&root)
        .iter()
        .filter_map(|case| case["call"].as_str())
        .collect();

    let missing: Vec<&str> = CALLS
        .iter()
        .copied()
        .filter(|call| !reached.contains(call))
        .collect();
    assert!(
        missing.is_empty(),
        "no fixture case calls {missing:?}. A call nothing reaches is a function three \
         clients are not held to, and it can go wrong in one of them with nothing going red."
    );

    // And the mirror: every call a case NAMES is one the door has.
    for case in cases(&root) {
        let call = case["call"].as_str().unwrap_or_default();
        assert!(
            CALLS.contains(&call),
            "case {}: no such call {call:?}",
            case["id"]
        );
    }

    // Both directions of the boundary, and a refusal, in every call that has
    // one. Counted rather than merely listed, because "some case refuses" is
    // satisfied by one row and this table's whole claim is that the shapes are
    // covered.
    let refusals = cases(&root)
        .iter()
        .filter(|case| !case["expectError"].is_null())
        .count();
    assert!(
        refusals >= 6,
        "only {refusals} refusal cases — the refusals ARE the contract for three of the \
         four calls, and a table with one of them says nothing about the rest"
    );
}

/// ONE NONCE PER PAIRING, asserted in Rust as well as in the file: the row
/// that holds the number's odds must say `interrupted`, and the rule must
/// release one nonce however many restarts and approvers a server lists.
#[test]
fn the_waiting_device_answers_one_exchange_per_pairing() {
    let root = fixture();
    let restart = cases(&root)
        .iter()
        .find(|case| case["id"] == "waiterStep/a-restart-after-a-shown-number-is-interrupted")
        .expect("the restart row is in the fixture");
    assert_eq!(restart["expect"]["waiterStep"], "interrupted");
    assert_ne!(restart["commitmentHex"], restart["boundCommitmentHex"]);
    assert_eq!(
        restart["approverDeviceId"],
        restart["boundApproverDeviceId"]
    );

    // A server restarting the same approver, and listing a fresh approver,
    // a hundred times each: the first answer binds and nothing after it is
    // answered.
    let key = [0xbb; 32];
    let mut bound: Option<(String, [u8; 32])> = None;
    let mut answered = 0;
    for attempt in 0u8..100 {
        let commitment = device_link_commitment(&[attempt; 32]).expect("commits");
        for approver in [
            "approver-ada-phone".to_string(),
            format!("listed-{attempt}"),
        ] {
            let (id, bound_key, bound_commitment) = match &bound {
                Some((id, c)) => (id.as_str(), &key[..], &c[..]),
                None => ("", &[][..], &[][..]),
            };
            let step = device_link_waiter_step(
                id,
                bound_key,
                bound_commitment,
                &approver,
                &key,
                &commitment,
            )
            .expect("well-formed");
            if step == DeviceLinkWaiterStep::Answer {
                answered += 1;
                bound = Some((approver.clone(), commitment));
            }
            if attempt > 0 && approver == "approver-ada-phone" {
                assert_eq!(step, DeviceLinkWaiterStep::Interrupted, "attempt {attempt}");
            }
        }
    }
    assert_eq!(answered, 1, "one nonce per pairing");
}

/// THE APPROVER'S RULE, asserted in Rust as well as in the file: the row that
/// holds the odds on the approving side says `interrupted`, and it has the
/// shape of the attack (a fixed nonce, another one listed, our reveal stored).
#[test]
fn the_approver_fixes_the_device_nonce_before_revealing() {
    let root = fixture();
    let row = cases(&root)
        .iter()
        .find(|case| {
            case["id"] == "approverStep/a-failed-reveal-then-another-device-nonce-is-interrupted"
        })
        .expect("the approver's row is in the fixture");
    assert_eq!(row["expect"]["approverStep"], "interrupted");
    assert_ne!(row["listedDeviceNonceHex"], row["boundDeviceNonceHex"]);
    assert_eq!(row["listedCommitmentHex"], row["commitmentHex"]);
    assert!(row["listedApproverNonceHex"]
        .as_str()
        .is_some_and(|hex| !hex.is_empty()));
}

#[test]
fn the_statement_and_the_code_are_what_the_fixture_says_they_are() {
    // Spot checks written out in Rust rather than read from the file, so that a
    // fixture which somehow round-trips its own mistakes still fails here.
    let laptop = [0x22u8; 32];
    let other = [0x33u8; 32];

    let statement = device_approval_statement("device-ada-laptop", &laptop).expect("a statement");
    let mut expected = Vec::new();
    expected.extend_from_slice(DEVICE_APPROVAL_DOMAIN.as_bytes());
    expected.push(0);
    expected.extend_from_slice(b"device-ada-laptop");
    expected.push(0);
    expected.extend_from_slice(&laptop);
    assert_eq!(statement, expected);
    // The domains are ASCII and the fixture writes them out in hex; a rename
    // of either one is a change to every golden value in the file.
    assert_eq!(DEVICE_APPROVAL_DOMAIN, "peachy-device-approval-v1");
    assert_eq!(DEVICE_LINK_COMMIT_DOMAIN, "peachy-device-link-commit-v1");
    assert_eq!(DEVICE_LINK_NUMBER_DOMAIN, "peachy-device-link-v2");
    assert_eq!(
        DEVICE_LINK_APPROVER_NUMBER_DOMAIN,
        "peachy-device-link-approver-v1"
    );

    let signature =
        sign_device_approval(&[0x11u8; 32], "device-ada-laptop", &laptop).expect("ada signs");
    let approver = signing_key_public_key(&[0x11u8; 32]).expect("a public half");
    assert!(verify_device_approval(
        &approver,
        "device-ada-laptop",
        &laptop,
        &signature
    ));

    // The order the number rests on: the approver's nonce must open the
    // commitment the new device saw first, and one key against itself is
    // refused rather than answered.
    let nonce_a = [0x66u8; 32];
    let nonce_n = [0x55u8; 32];
    let commitment = device_link_commitment(&nonce_a).expect("commits");
    let number = device_link_number(&laptop, &other, &commitment, &nonce_n, &nonce_a)
        .expect("an ordinary number");
    assert_eq!(number.len(), 2);
    let err = device_link_number(&laptop, &other, &commitment, &nonce_n, &nonce_n)
        .expect_err("a nonce that was never committed");
    assert!(err.to_string().contains("commitment"), "{err}");
    let err =
        device_link_number(&laptop, &laptop, &commitment, &nonce_n, &nonce_a).expect_err("refused");
    assert!(err.to_string().contains("itself"), "{err}");

    // The approver's number is the same inputs under another domain.
    let second = device_link_approver_number(&laptop, &other, &commitment, &nonce_n, &nonce_a)
        .expect("an ordinary number");
    assert_eq!(second.len(), 2);

    // And the QR code is the whole key and the secret, matched only by itself.
    let secret = [0x5eu8; 32];
    let qr = device_link_qr("device-ada-laptop", &laptop, &secret).expect("a code");
    assert!(
        qr.ends_with(&format!("{}/{}", "22".repeat(32), "5e".repeat(32))),
        "{qr}"
    );
    assert!(device_link_qr_matches(&qr, "device-ada-laptop", &laptop));
    assert!(!device_link_qr_matches(&qr, "device-ada-laptop", &other));
    assert_eq!(
        device_link_qr_secret(&qr, "device-ada-laptop", &laptop),
        Some(secret)
    );
}

#[test]
fn a_key_packages_identity_comes_out_of_its_own_bytes() {
    // The fifth call, asserted end to end in Rust rather than only through the
    // table — a client really produces a key package, a different client really
    // reads it, and the signing key that comes back is the one the producer
    // actually holds.
    let issuer = TestIssuer::from_seed(&[0x07u8; 32]);
    let device_seed = [0x33u8; 32];
    let (_, device_key) = device_key_pair(&device_seed);
    let now = 1_789_516_800i64;

    let producer = Client::new(ClientConfig {
        clock: Some(Box::new(FixedClock(now))),
        ..ClientConfig::new(
            issuer
                .issue(
                    "actor-ada",
                    "device-ada-laptop",
                    &device_key,
                    now - 3600,
                    now + 3600,
                )
                .expect("a credential"),
            device_seed,
            issuer.trusted_keys().expect("the issuer's key"),
        )
        .with_own_account_identity(Some(held("actor-ada")))
    })
    .expect("the producing device opens");
    let key_package = producer.generate_key_package().expect("a key package");

    let reader = Client::new(ClientConfig {
        clock: Some(Box::new(FixedClock(now))),
        ..ClientConfig::new(
            issuer
                .issue(
                    "actor-bo",
                    "device-bo-phone",
                    &device_key_pair(&[0x44u8; 32]).1,
                    now - 3600,
                    now + 3600,
                )
                .expect("a credential"),
            [0x44u8; 32],
            issuer.trusted_keys().expect("the issuer's key"),
        )
        .with_own_account_identity(Some(held("actor-bo")))
    })
    .expect("the reading device opens");

    let identity = reader
        .key_package_identity(&key_package)
        .expect("these bytes are a key package")
        .expect("and its credential verifies");
    assert_eq!(identity.actor_id, "actor-ada");
    assert_eq!(identity.device_id, "device-ada-laptop");
    // THE assertion. The key the reader hands to `verify_device_approval` is
    // the producer's own, taken out of the package, and nobody in between got
    // to name it.
    assert_eq!(identity.device_key, device_key);

    // And an approval over that key, checked exactly the way an adder would.
    let approver_seed = [0x11u8; 32];
    let approval = sign_device_approval(&approver_seed, &identity.device_id, &identity.device_key)
        .expect("ada's other device approves the laptop");
    assert!(verify_device_approval(
        &signing_key_public_key(&approver_seed).expect("the approver's public half"),
        &identity.device_id,
        &identity.device_key,
        &approval
    ));

    // Bytes that are not a key package are a REFUSAL, not a rejection: a caller
    // must not be able to report "that device's credential is bad" about
    // something that was never a credential.
    reader
        .key_package_identity(&[0xDE, 0xAD, 0xBE, 0xEF])
        .expect_err("four bytes of nonsense are not a key package");

    // A reader whose clock has moved past the credential gets a VERDICT it can
    // explain, from the very same bytes.
    let late = Client::new(ClientConfig {
        clock: Some(Box::new(FixedClock(now + 86_400))),
        ..ClientConfig::new(
            issuer
                .issue(
                    "actor-bo",
                    "device-bo-phone",
                    &device_key_pair(&[0x44u8; 32]).1,
                    now + 86_000,
                    now + 90_000,
                )
                .expect("a credential"),
            [0x44u8; 32],
            issuer.trusted_keys().expect("the issuer's key"),
        )
        .with_own_account_identity(Some(held("actor-bo")))
    })
    .expect("the late reader opens");
    assert_eq!(
        late.key_package_identity(&key_package)
            .expect("still a key package")
            .expect_err("but not one it will believe"),
        CredentialRejection::Expired
    );
}

#[test]
fn a_case_that_addresses_nothing_real_is_an_error_and_not_a_verdict() {
    // The distinction the whole replay rests on. A case naming something that
    // no longer exists has to fail loudly — the alternative is a fixture that
    // goes on passing while it tests nothing.
    let err = evaluate_case_json(
        r#"{"kind":"device_link","call":"compareEverything","deviceId":"d","signingKeyHex":"22"}"#,
    )
    .expect_err("an unknown call is refused");
    assert!(err.to_string().contains("compareEverything"), "{err}");
    // And it lists what IS known, so repointing a case is a read rather than a
    // search.
    assert!(err.to_string().contains("statement"), "{err}");
    assert!(err.to_string().contains("number"), "{err}");

    let err = evaluate_case_json(r#"{"kind":"teleport"}"#).expect_err("an unknown kind is refused");
    assert!(err.to_string().contains("teleport"), "{err}");
    assert!(err.to_string().contains("device_link"), "{err}");

    // A missing field names what is missing rather than defaulting to
    // something that would quietly hash or sign the wrong thing.
    let err = evaluate_case_json(r#"{"kind":"device_link","call":"number"}"#)
        .expect_err("a number case needs its inputs");
    assert!(err.to_string().contains("`newDeviceKeyHex`"), "{err}");

    let err = evaluate_case_json(r#"{"kind":"device_link","call":"statement","deviceId":"d"}"#)
        .expect_err("a statement case needs a key");
    assert!(err.to_string().contains("`signingKeyHex`"), "{err}");

    // Hex that is not hex, and hex of an odd length, are case-author mistakes
    // and not inputs: a truncated string would silently become different bytes.
    let err =
        evaluate_case_json(r#"{"kind":"device_link","call":"commitment","approverNonceHex":"zz"}"#)
            .expect_err("non-hex is refused");
    assert!(err.to_string().contains("is not hex"), "{err}");

    let err = evaluate_case_json(
        r#"{"kind":"device_link","call":"commitment","approverNonceHex":"222"}"#,
    )
    .expect_err("odd-length hex is refused");
    assert!(
        err.to_string().contains("even number of hex characters"),
        "{err}"
    );
}

#[test]
fn the_other_two_tables_are_untouched_by_the_new_kind() {
    // `rules.json` carries no `kind` and must go on meaning the policy table;
    // `credentials.json` names its own. This is the assertion that would catch
    // the new arm swallowing either.
    let out =
        evaluate_case_json(r#"{"call":"evaluate","proposal":{"kind":"add","sender":"member"}}"#)
            .expect("a case with no kind is a rules case");
    assert_eq!(out, r#"{"decision":"allow"}"#);

    let err = evaluate_case_json(
        r#"{"kind":"credential","call":"validateNothing","nowUnix":0,
        "trust":[],"token":"pdc1",
        "leafSeed":"1111111111111111111111111111111111111111111111111111111111111111"}"#,
    )
    .expect_err("a credential case still reaches the credential door");
    assert!(err.to_string().contains("validateCredential"), "{err}");
}
