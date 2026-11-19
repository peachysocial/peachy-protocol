// SPDX-License-Identifier: MIT
//! The golden Welcome-frame fixture, replayed against the real implementation.
//!
//! `mls/fixtures/welcome-frame.json` pins the padded Welcome frame
//! (`mls/core/src/welcome_frame.rs`): its bytes, its target's rounding, what a
//! reader accepts and refuses: every add and reseat is sent framed, and
//! anything that is not a frame is refused.
//! This is the Rust half of its replay; `mls/wasm/tests/node/welcome-frame.test.mjs`,
//! `mls/swift/Tests/PeachyMLSTests/WelcomeFrameFixtureTests.swift` and
//! the Android binding's `WelcomeFrameFixtureTest` (not in this repository) make the
//! same calls through the same door, and each also joins a group from a framed
//! real Welcome through its product door, as the last test here does.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::collections::BTreeSet;

use peachy_mls_core::fixture::evaluate_case_json;
use peachy_mls_core::welcome_frame::unframe_welcome;
use serde_json::{json, Value};
use support::{client, issuer};

const FIXTURE: &str = include_str!("../../fixtures/welcome-frame.json");

fn cases() -> Vec<Value> {
    let root: Value = serde_json::from_str(FIXTURE).expect("welcome-frame.json is valid JSON");
    assert_eq!(root["version"], 1);
    root["cases"]
        .as_array()
        .expect("`cases` is an array")
        .clone()
}

#[test]
fn every_welcome_frame_case_gets_the_verdict_it_expects() {
    let cases = cases();
    assert!(cases.len() >= 20, "only {} cases", cases.len());
    let mut ids = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut failures = Vec::new();
    for case in &cases {
        let id = case["id"]
            .as_str()
            .expect("every case has an id")
            .to_string();
        assert!(ids.insert(id.clone()), "two cases share the id {id:?}");
        assert_eq!(case["kind"], "welcome_frame", "case {id}");
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
        "frame",
        "paddedLen",
        "unframe",
        "sealGap",
        "openGap",
    ] {
        assert!(calls.contains(call), "no `{call}` case");
    }
}

/// The product door: a real Welcome, framed by the fixture door, seats its
/// joiner through `join_from_welcome`, and a frame with a stray fill byte
/// does not. The stray frame goes last: a refused frame spends its key
/// package, so trying it first would leave the clean one nothing to open.
#[test]
fn a_framed_real_welcome_seats_its_joiner() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let group = b"welcome-frame-room";
    ada.create_group(group).unwrap();
    let kp = bo.generate_key_package().unwrap();
    let bundle = ada.add_member(group, &kp).unwrap();
    ada.merge_pending_commit(group).unwrap();
    // The raw MLS Welcome inside what the adder sent, to frame here.
    let welcome = unframe_welcome(&bundle.welcome.unwrap()).unwrap().to_vec();

    let framed = evaluate_case_json(
        &json!({
            "kind": "welcome_frame",
            "call": "frame",
            "welcomeHex": hex::encode(&welcome),
            "paddedLen": welcome.len() + 1024,
        })
        .to_string(),
    )
    .unwrap();
    let framed: Value = serde_json::from_str(&framed).unwrap();
    let framed = hex::decode(framed["framedHex"].as_str().unwrap()).unwrap();
    assert_eq!(framed.len(), welcome.len() + 1024);

    assert_eq!(bo.join_from_welcome(&framed).unwrap(), group.to_vec());
    let sent = ada.encrypt(group, b"hello").unwrap();
    assert!(bo.process_message(group, &sent).is_ok());

    let mut stray = framed.clone();
    *stray.last_mut().unwrap() = 1;
    let err = bo.join_from_welcome(&stray).unwrap_err().to_string();
    assert!(err.contains("fill"), "{err}");
}
