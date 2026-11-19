// SPDX-License-Identifier: MIT
//! The typing fixture, replayed against the core through the fixture door.
//!
//! `mls/fixtures/formats/typing.json` carries two tables: `cases`, the
//! unsigned frame every build still opens, and `signedCases`, the signed and
//! stamped frame the core writes (`mls/core/src/typing.rs`), which only the
//! core replays because only the core seals or opens a real frame. Both go
//! through `evaluate_case_json` here, so the core reads and writes the same
//! unsigned bytes as every reader of the older frame.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use peachy_mls_core::fixture::evaluate_case_json;
use serde_json::{json, Value};

const FIXTURE: &str = include_str!("../../fixtures/formats/typing.json");

fn root() -> Value {
    serde_json::from_str(FIXTURE).expect("typing.json is valid JSON")
}

fn run(case: &Value) -> Value {
    let actual = evaluate_case_json(&case.to_string())
        .unwrap_or_else(|err| panic!("case {}: the door refused it: {err}", case["id"]));
    serde_json::from_str(&actual).unwrap()
}

#[test]
fn every_signed_case_gets_the_verdict_it_expects() {
    let root = root();
    let cases = root["signedCases"]
        .as_array()
        .expect("`signedCases` is an array");
    assert!(cases.len() >= 10, "only {} signed cases", cases.len());
    let mut failures = Vec::new();
    for case in cases {
        assert_eq!(case["kind"], "typing", "case {}", case["id"]);
        let actual = run(case);
        if actual != case["expect"] {
            failures.push(format!(
                "  {}\n    expected {}\n    actual   {actual}",
                case["id"], case["expect"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} cases disagree:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The codec table (the frame without `g` and `s`), in the clients' own
/// shape, through the core's codec: the bytes it pins are the bytes the core
/// reads.
#[test]
fn the_core_reads_and_writes_the_unsigned_frame_the_clients_pin() {
    let root = root();
    let label = root["label"].as_str().unwrap();
    assert_eq!(label, "peachy typing v1");
    let mut replayed = 0;
    for case in root["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let frame_of = |v: &Value| {
            if v.is_null() {
                Value::Null
            } else {
                json!({ "actorId": v["actorId"], "typing": v["typing"] })
            }
        };
        match case["call"].as_str().unwrap() {
            "encode" => {
                let out = run(&json!({
                    "kind": "typing", "call": "encode", "id": id,
                    "frame": { "actorId": case["typing"]["actorId"], "typing": case["typing"]["typing"] },
                }));
                let wire = out["wire"].as_str().unwrap();
                let parsed =
                    run(&json!({ "kind": "typing", "call": "parse", "id": id, "wire": wire }));
                assert_eq!(parsed["frame"], frame_of(&case["expect"]), "{id}");
                let keys: Vec<String> =
                    serde_json::from_str::<serde_json::Map<String, Value>>(wire)
                        .unwrap()
                        .keys()
                        .cloned()
                        .collect();
                assert_eq!(json!(keys), case["keys"], "{id}");
            }
            "parse" => {
                let parsed = run(
                    &json!({ "kind": "typing", "call": "parse", "id": id, "wire": case["wire"] }),
                );
                assert_eq!(parsed["frame"], frame_of(&case["expect"]), "{id}");
            }
            "seal" => {
                let wire = run(&json!({
                    "kind": "typing", "call": "encode", "id": id,
                    "frame": { "actorId": case["typing"]["actorId"], "typing": case["typing"]["typing"] },
                }))["wire"]
                    .clone();
                let sealed = run(&json!({
                    "kind": "typing", "call": "seal", "id": id,
                    "key": case["key"], "nonce": case["nonce"], "wire": wire,
                }));
                assert_eq!(sealed["frame"], case["frame"], "{id}");
            }
            "open" => {
                let opened = run(&json!({
                    "kind": "typing", "call": "open", "id": id, "key": case["key"], "frame": case["frame"],
                }));
                let frame = match opened["wire"].as_str() {
                    None => Value::Null,
                    Some(wire) => {
                        run(&json!({ "kind": "typing", "call": "parse", "id": id, "wire": wire }))
                            ["frame"]
                            .clone()
                    }
                };
                assert_eq!(frame, frame_of(&case["expect"]), "{id}");
            }
            other => panic!("{id}: unknown call {other}"),
        }
        replayed += 1;
    }
    assert!(replayed >= 15, "only {replayed} unsigned cases");
}
