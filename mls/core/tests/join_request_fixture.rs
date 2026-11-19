// SPDX-License-Identifier: MIT
//! The golden join-request fixture, replayed against the real implementation.
//!
//! `mls/fixtures/join-request.json` pins what a requesting device signs to be
//! seated in a group and what an admitting device decides about it
//! (`mls/core/src/join_request.rs`, and the two `Client` doors). This is the
//! Rust half of its replay; `mls/wasm/tests/node/join-request.test.mjs` is the
//! JavaScript half, and Swift and Kotlin reach the same door across C.
//!
//! What it holds: every case's verdict or refusal, every call reached, every
//! verdict reached and carrying its true number, and the attack the table
//! exists for present by name.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use peachy_mls_core::fixture::{evaluate_case_json, FORMAT_VERSION};
use peachy_mls_core::JoinRequestVerdict;
use serde_json::Value;

const FIXTURE: &str = include_str!("../../fixtures/join-request.json");

const CALLS: [&str; 4] = ["statement", "sign", "verify", "roundTrip"];

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("mls/fixtures/join-request.json is valid JSON")
}

fn cases(root: &Value) -> &Vec<Value> {
    root["cases"].as_array().expect("`cases` is an array")
}

#[test]
fn the_fixture_declares_its_format_and_kind() {
    let root = fixture();
    assert_eq!(root["version"].as_u64(), Some(u64::from(FORMAT_VERSION)));
    assert!(
        cases(&root).len() >= 28,
        "only {} cases — the fixture shrank or stopped parsing",
        cases(&root).len()
    );
    for case in cases(&root) {
        assert_eq!(
            case["kind"].as_str(),
            Some("join_request"),
            "case {} has no `kind`: \"join_request\"",
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
        "{} of {} join-request cases disagree with mls/core/src/join_request.rs:\n{}",
        failures.len(),
        cases(&root).len(),
        failures.join("\n")
    );
}

#[test]
fn every_call_is_reached_and_an_unknown_one_is_refused() {
    let root = fixture();
    let reached: BTreeSet<&str> = cases(&root)
        .iter()
        .filter_map(|case| case["call"].as_str())
        .collect();
    for call in CALLS {
        assert!(reached.contains(call), "no case calls {call:?}");
    }
    let err = evaluate_case_json(r#"{"kind":"join_request","call":"teleport"}"#)
        .expect_err("an unknown call is refused");
    assert!(err.to_string().contains("teleport"), "{err}");
}

#[test]
fn every_verdict_is_reached_with_its_true_number() {
    let root = fixture();
    let mut reached = BTreeSet::new();
    for case in cases(&root) {
        let Some(name) = case["expect"]["verdict"].as_str() else {
            continue;
        };
        let code = case["expect"]["verdictCode"].as_u64().expect("a code") as u32;
        let verdict = JoinRequestVerdict::from_code(code).expect("a real code");
        assert_eq!(
            verdict.name(),
            name,
            "case {} names the wrong number",
            case["id"]
        );
        reached.insert(code);
    }
    for verdict in JoinRequestVerdict::ALL {
        assert!(
            reached.contains(&verdict.code()),
            "no case reaches {:?}; a verdict nothing reaches is a branch the fixture cannot \
             protect",
            verdict.name()
        );
    }
}

#[test]
fn the_forgery_this_table_exists_for_is_refused() {
    let root = fixture();
    let case = cases(&root)
        .iter()
        .find(|case| case["id"] == "bad_signature/a-member-signs-for-ada")
        .expect("the forged-request case is present by name");
    let verdict: Value =
        serde_json::from_str(&evaluate_case_json(&case.to_string()).expect("a verdict"))
            .expect("JSON");
    assert_eq!(verdict["verdict"], "bad_signature");
}
