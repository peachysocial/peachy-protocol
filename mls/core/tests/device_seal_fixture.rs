// SPDX-License-Identifier: MIT
//! The golden device-seal fixture, replayed against the real implementation.
//!
//! `mls/fixtures/device-seal.json` pins the device seal
//! (`mls/core/src/device_seal.rs`): its bytes for given inputs, what opens and
//! what is refused, and that no build SENDS it (`DEVICE_SEAL_SENDS` is
//! false). This is the Rust
//! half of its replay; `mls/wasm/tests/node/device-seal.test.mjs`,
//! `mls/swift/Tests/PeachyMLSTests/DeviceSealFixtureTests.swift` and
//! the Android binding's `DeviceSealFixtureTest` (not in this repository) make the
//! same calls through the same door.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use peachy_mls_core::fixture::evaluate_case_json;
use serde_json::Value;

const FIXTURE: &str = include_str!("../../fixtures/device-seal.json");

#[test]
fn every_device_seal_case_gets_the_verdict_it_expects() {
    let root: Value = serde_json::from_str(FIXTURE).expect("device-seal.json is valid JSON");
    assert_eq!(root["version"], 1);
    let cases = root["cases"].as_array().expect("`cases` is an array");
    assert!(cases.len() >= 20, "only {} cases", cases.len());
    let mut ids = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut failures = Vec::new();
    for case in cases {
        let id = case["id"]
            .as_str()
            .expect("every case has an id")
            .to_string();
        assert!(ids.insert(id.clone()), "two cases share the id {id:?}");
        assert_eq!(case["kind"], "device_seal", "case {id}");
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
    for call in ["constants", "seal", "open"] {
        assert!(calls.contains(call), "no `{call}` case");
    }
}
