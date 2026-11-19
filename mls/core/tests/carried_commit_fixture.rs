// SPDX-License-Identifier: MIT
//! The golden carried-commit fixture, replayed against the real
//! implementation.
//!
//! `mls/fixtures/carried-commit.json` pins the carried commit
//! (`mls/core/src/carried_commit.rs`): its bytes, what a reader accepts and
//! refuses, and the frame's constants. This is the Rust
//! half of its replay; `mls/wasm/tests/node/carried-commit.test.mjs`,
//! `mls/swift/Tests/PeachyMLSTests/CarriedCommitFixtureTests.swift` and
//! the Android binding's `CarriedCommitFixtureTest` (not in this repository) make
//! the same calls through the same door. A real leave carried through the
//! commit door is `mls/core/tests/leave_lands.rs`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use peachy_mls_core::fixture::evaluate_case_json;
use serde_json::Value;

const FIXTURE: &str = include_str!("../../fixtures/carried-commit.json");

#[test]
fn every_carried_commit_case_gets_the_verdict_it_expects() {
    let root: Value = serde_json::from_str(FIXTURE).expect("carried-commit.json is valid JSON");
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
        assert_eq!(case["kind"], "carried_commit", "case {id}");
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
    for call in ["constants", "carry", "split"] {
        assert!(calls.contains(call), "no `{call}` case");
    }
}
