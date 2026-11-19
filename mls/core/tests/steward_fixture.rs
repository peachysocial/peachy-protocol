// SPDX-License-Identifier: MIT
//! The golden steward fixture, replayed against the real implementation.
//!
//! `mls/fixtures/steward.json` pins the steward key's statements, the veto
//! frame and how it nests around a carried frame, the commit MAC, the sealed
//! stamp, the head log copy, the repair notice and the meta's `stw.k`
//! (`mls/core/src/steward.rs`). This is the Rust half of its replay;
//! `mls/wasm/tests/node/steward.test.mjs`,
//! `mls/swift/Tests/PeachyMLSTests/StewardFixtureTests.swift` and
//! the Android binding's `StewardFixtureTest` (not in this repository) make the
//! same calls through the same door. The behavior around it is
//! `mls/core/tests/insider_stall.rs`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use peachy_mls_core::fixture::evaluate_case_json;
use serde_json::Value;

const FIXTURE: &str = include_str!("../../fixtures/steward.json");

#[test]
fn every_steward_case_gets_the_verdict_it_expects() {
    let root: Value = serde_json::from_str(FIXTURE).expect("steward.json is valid JSON");
    assert_eq!(root["version"], 1);
    let cases = root["cases"].as_array().expect("`cases` is an array");
    assert!(cases.len() >= 30, "only {} cases", cases.len());
    let mut ids = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut failures = Vec::new();
    for case in cases {
        let id = case["id"]
            .as_str()
            .expect("every case has an id")
            .to_string();
        assert!(ids.insert(id.clone()), "two cases share the id {id:?}");
        assert_eq!(case["kind"], "steward", "case {id}");
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
    for call in [
        "constants",
        "public_key",
        "statement",
        "wrap_veto",
        "split",
        "verify_veto",
        "mac",
        "seal_stamp",
        "open_stamp",
        "seal_log_copy",
        "open_log_copy",
        "repair_notice",
        "meta_key",
    ] {
        assert!(calls.contains(call), "no `{call}` case");
    }
}
