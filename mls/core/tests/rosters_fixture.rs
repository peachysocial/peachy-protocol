// SPDX-License-Identifier: MIT
//! `mls/fixtures/rosters.json`, replayed against the real handle, envelope
//! and group policy (docs/delivery.md §Handles and sender-addressed delivery).
//!
//! The fixture's bytes were written by an independent implementation, so a
//! pass here is two implementations agreeing. The JavaScript, Swift and Kotlin
//! replays make the same call through the same door.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use peachy_mls_core::fixture::evaluate_case_json;
use serde_json::Value;

const FIXTURE: &str = include_str!("../../fixtures/rosters.json");

#[test]
fn every_roster_case_gets_the_verdict_it_expects() {
    let root: Value = serde_json::from_str(FIXTURE).expect("rosters.json is valid JSON");
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
    for call in ["handle", "seal", "open", "judge"] {
        assert!(calls.contains(call), "no `{call}` case");
    }
}
