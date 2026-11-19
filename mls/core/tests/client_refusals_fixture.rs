// SPDX-License-Identifier: MIT
//! The golden client-refusals fixture, replayed against the real table.
//!
//! `mls/fixtures/client-refusals.json` lists every refusal the delivery
//! service can switch on, with this build's compiled default, and pins the
//! one-way rule (`mls/core/src/client_refusals.rs`). This is the Rust half of
//! its replay; `mls/wasm/tests/node/client-refusals.test.mjs`,
//! `mls/swift/Tests/PeachyMLSTests/ClientRefusalsFixtureTests.swift` and
//! the Android binding's `ClientRefusalsFixtureTest` (not in this repository) make
//! the same calls through the same door.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use peachy_mls_core::fixture::evaluate_case_json;
use peachy_mls_core::CLIENT_REFUSALS;
use serde_json::Value;

const FIXTURE: &str = include_str!("../../fixtures/client-refusals.json");

#[test]
fn every_client_refusals_case_gets_the_verdict_it_expects() {
    let root: Value = serde_json::from_str(FIXTURE).expect("client-refusals.json is valid JSON");
    assert_eq!(root["version"], 1);
    let cases = root["cases"].as_array().expect("`cases` is an array");
    let mut ids = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut failures = Vec::new();
    for case in cases {
        let id = case["id"]
            .as_str()
            .expect("every case has an id")
            .to_string();
        assert!(ids.insert(id.clone()), "two cases share the id {id:?}");
        assert_eq!(case["kind"], "client_refusals", "case {id}");
        calls.insert(case["call"].as_str().unwrap().to_string());
        let actual = evaluate_case_json(&case.to_string())
            .unwrap_or_else(|err| panic!("case {id}: the door refused it: {err}"));
        let actual: Value = serde_json::from_str(&actual).unwrap();
        if actual != case["expect"] {
            failures.push(format!(
                "  {id}\n    expected {}\n    actual   {actual}",
                case["expect"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} cases disagree:\n{}",
        failures.len(),
        failures.join("\n")
    );
    for call in ["table", "ratchet", "on"] {
        assert!(calls.contains(call), "no `{call}` case");
    }
}

/// The top-level table names each refusal, its default and its constant, the
/// same as the core's own.
#[test]
fn the_fixture_table_is_the_cores() {
    let root: Value = serde_json::from_str(FIXTURE).unwrap();
    let table = root["refusals"].as_array().expect("`refusals` is an array");
    assert_eq!(table.len(), CLIENT_REFUSALS.len());
    for (row, refusal) in table.iter().zip(CLIENT_REFUSALS) {
        assert_eq!(row["name"], refusal.name);
        assert_eq!(row["compiledDefault"], refusal.compiled_default);
        assert_eq!(row["drives"], refusal.drives);
    }
}
