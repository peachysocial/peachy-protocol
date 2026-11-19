// SPDX-License-Identifier: MIT
//! The golden credential fixture, replayed against the real identity layer.
//!
//! `mls/fixtures/credentials.json` is a table of (inputs, expected verdict)
//! covering every way a `pdc1` device credential can fail to make a leaf into
//! somebody. This file is the Rust half of its replay;
//! `mls/wasm/tests/node/credentials.test.mjs` is the JavaScript half, through
//! the wasm binding, and Swift and Kotlin reach the same door across C.
//! docs/mls-core.md §Golden credential fixture is the reading guide.
//!
//! It is the sibling of `rules_fixture.rs`, and the pair is the whole of what
//! the four clients have to agree on before any of them ships:
//! `rules.json` pins what the GROUP POLICY decides about a proposal,
//! `credentials.json` pins what the IDENTITY layer decides about a leaf.
//!
//! ## What this actually holds
//!
//! 1. **Every case's verdict is the verifier's verdict.** The obvious half.
//! 2. **Every `CredentialRejection` is reached by some case**, checked against
//!    `CredentialRejection::ALL`. A rejection nothing produces is a branch this
//!    fixture cannot protect, and it could go wrong in one client without
//!    anything anywhere going red.
//! 3. **Every reason a case *names* is real and carries its true code.** A typo
//!    in an `expect` would otherwise be caught only indirectly, by a mismatch
//!    message that is about a difference rather than about a name that does not
//!    exist.
//! 4. **An acceptance carries the identity, not just the word.** A verdict of
//!    "accepted" and nothing else reads the same from a verifier that had
//!    stopped looking at the payload.
//!
//! The fixture is read with `include_str!`, so a file that moves is a COMPILE
//! error and a JSON typo is a parse failure, rather than a test that quietly
//! finds zero cases and reports success.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use peachy_mls_core::fixture::{evaluate_case_json, FORMAT_VERSION};
use peachy_mls_core::CredentialRejection;
use serde_json::Value;

const FIXTURE: &str = include_str!("../../fixtures/credentials.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("mls/fixtures/credentials.json is valid JSON")
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
        cases(&root).len() >= 35,
        "only {} cases — the fixture shrank or stopped parsing",
        cases(&root).len()
    );

    // Every case says which table it belongs to. The door defaults an absent
    // `kind` to `rules`, which is what keeps `rules.json` working unchanged —
    // and which would silently send a credential case to the policy layer,
    // where its `call` would be refused rather than answered wrongly. Loud
    // either way, but this says so in one line instead of thirty-nine.
    for case in cases(&root) {
        assert_eq!(
            case["kind"].as_str(),
            Some("credential"),
            "case {} has no `kind`: \"credential\"",
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

        // The whole case object goes to the door, `expect` and `why` included
        // and ignored — the same call the wasm, Swift and Kotlin replays make.
        let actual = evaluate_case_json(&case.to_string())
            .unwrap_or_else(|err| panic!("case {id}: the verifier refused to evaluate it: {err}"));
        let actual: Value =
            serde_json::from_str(&actual).expect("the door returns JSON it wrote itself");

        let expected = &case["expect"];
        if &actual != expected {
            failures.push(format!(
                "  {id}\n    expected {expected}\n    actual   {actual}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} fixture cases disagree with the identity layer.\n\
         Either mls/core/src/identity.rs or mls/core/src/credential.rs changed a decision — \
         in which case every client changed with it and the fixture is the record of that — \
         or the fixture is wrong.\n{}",
        failures.len(),
        cases(&root).len(),
        failures.join("\n")
    );
}

#[test]
fn every_rejection_is_reached_by_some_case() {
    let root = fixture();

    let reached: BTreeSet<&str> = cases(&root)
        .iter()
        .filter_map(|case| case["expect"]["reason"].as_str())
        .collect();

    let missing: Vec<&str> = CredentialRejection::ALL
        .iter()
        .map(|rejection| rejection.name())
        .filter(|name| !reached.contains(name))
        .collect();

    assert!(
        missing.is_empty(),
        "no fixture case produces {missing:?}. A rejection nothing reaches is a branch \
         this fixture cannot protect, and it can go wrong in one client with nothing going red."
    );

    // And the mirror: every reason a case NAMES is a real one, carrying the
    // number the fixture claims for it. These are the two ways this contract
    // breaks — a rename that left the discriminant alone, and a renumbering
    // that left the name alone.
    for case in cases(&root) {
        if let Some(name) = case["expect"]["reason"].as_str() {
            let rejection = CredentialRejection::from_name(name)
                .unwrap_or_else(|| panic!("no such credential rejection: {name:?}"));
            assert_eq!(
                case["expect"]["reasonCode"].as_u64(),
                Some(u64::from(rejection.code())),
                "case {}: reason {name:?} is code {}, not what the fixture says",
                case["id"],
                rejection.code()
            );
        }
    }
}

#[test]
fn an_acceptance_names_who_it_accepted() {
    let root = fixture();

    let accepted: Vec<&Value> = cases(&root)
        .iter()
        .filter(|case| case["expect"]["decision"] == "accepted")
        .collect();

    assert!(
        accepted.len() >= 5,
        "only {} accept cases. The rejections are only meaningful beside credentials that \
         DO check out — otherwise a verifier that refused everything would pass most of this file.",
        accepted.len()
    );

    for case in accepted {
        // A verdict of "accepted" and nothing else reads the same from a
        // verifier that had stopped reading the payload. These four fields are
        // the KEY layer of identity (docs/identity.md) and no display name
        // appears among them, here or anywhere in this crate.
        for field in ["actorId", "deviceId", "kid", "expiresAt"] {
            assert!(
                !case["expect"][field].is_null(),
                "case {}: an acceptance has to say {field}",
                case["id"]
            );
        }
        assert!(
            case["expect"]["reason"].is_null() && case["expect"]["reasonCode"].is_null(),
            "case {}: an acceptance carries no reason",
            case["id"]
        );
    }
}

#[test]
fn a_case_that_addresses_nothing_real_is_an_error_and_not_a_verdict() {
    // The distinction the whole replay rests on, spelled out in Rust rather
    // than read from the file so that a fixture which round-trips its own
    // mistakes still fails here.
    let err = evaluate_case_json(
        r#"{"kind":"credential","call":"validateNothing","nowUnix":0,"trust":[],"token":"pdc1",
            "leafSeed":"1111111111111111111111111111111111111111111111111111111111111111"}"#,
    )
    .expect_err("an unknown call is refused");
    assert!(err.to_string().contains("validateNothing"), "{err}");
    assert!(err.to_string().contains("validateCredential"), "{err}");

    let err = evaluate_case_json(r#"{"kind":"teleport"}"#).expect_err("an unknown kind is refused");
    assert!(err.to_string().contains("teleport"), "{err}");
    assert!(err.to_string().contains("credential"), "{err}");

    // A seed of the wrong length is the case-author error most likely to look
    // like a verdict if it were tolerated: a truncated hex string would
    // silently become a different key and a different `kid`.
    let err = evaluate_case_json(
        r#"{"kind":"credential","call":"validateToken","nowUnix":0,"trust":["07"],"token":"pdc1","leafSeed":"1111111111111111111111111111111111111111111111111111111111111111"}"#,
    )
    .expect_err("a short seed is refused");
    assert!(err.to_string().contains("64 hex characters"), "{err}");

    let err = evaluate_case_json(
        r#"{"kind":"credential","call":"validateToken","nowUnix":0,"trust":[]}"#,
    )
    .expect_err("a case with no credential at all is refused");
    assert!(err.to_string().contains("`mint` or a `token`"), "{err}");
}

#[test]
fn the_rules_half_of_the_door_is_untouched_by_the_new_kind() {
    // `rules.json` carries no `kind`, and it must go on meaning the policy
    // table. This is the one assertion that would catch a dispatch defaulting
    // the other way — which would leave both fixtures green in Rust and red in
    // three bindings built from an older commit.
    let out =
        evaluate_case_json(r#"{"call":"evaluate","proposal":{"kind":"add","sender":"member"}}"#)
            .expect("a case with no kind is a rules case");
    assert_eq!(out, r#"{"decision":"allow"}"#);

    let out = evaluate_case_json(
        r#"{"kind":"rules","call":"evaluate","proposal":{"kind":"add","sender":"member"}}"#,
    )
    .expect("and naming the kind explicitly says the same");
    assert_eq!(out, r#"{"decision":"allow"}"#);
}
