// SPDX-License-Identifier: MIT
//! The golden fixture, replayed against the real policy.
//!
//! `mls/fixtures/rules.json` is a table of (inputs, expected verdict) covering
//! every decision `peachy_mls_core::rules` makes. This file is the Rust half of
//! its replay; `mls/wasm/tests/node/rules.test.mjs` is the JavaScript half,
//! through the wasm binding. docs/mls-core.md §Golden rules
//! fixture is the reading guide: one table, replayed by every binding before
//! any client ships.
//!
//! ## What this actually holds
//!
//! Three things, and the third is the one a plain table of assertions would
//! miss:
//!
//! 1. **Every case's verdict is the policy's verdict.** The obvious half.
//! 2. **The fixture is EXHAUSTIVE over sender × kind.** All 4 × 9 cells have a
//!    case, checked against `SenderKind::ALL` and `ProposalKind::ALL`, whose
//!    lengths are written down in `rules.rs`. So adding a proposal type fails
//!    here until somebody writes down, in prose a reader can check, what Peachy
//!    says about it. A policy nobody wrote down is a policy four clients will
//!    each guess at differently.
//! 3. **Every `DenyReason` is reached by some case.** A reason no case produces
//!    is a branch this fixture cannot protect, and it would silently become
//!    unreachable in one client without anything going red.
//!
//! The fixture is read with `include_str!`, so a file that moves or a JSON
//! typo is a COMPILE error and a parse failure respectively, rather than a test
//! that quietly finds zero cases and reports success.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use peachy_mls_core::fixture::{evaluate_case_json, FORMAT_VERSION};
use peachy_mls_core::rules::{DenyReason, ProposalKind, SenderKind};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../fixtures/rules.json");
const ROSTERS: &str = include_str!("../../fixtures/rosters.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("mls/fixtures/rules.json is valid JSON")
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

    // A floor, so that a replay which stopped finding cases cannot read as a
    // clean pass over nothing — the failure this whole file exists to make
    // impossible. Under today's count on purpose, so growth never rewrites it.
    assert!(
        cases(&root).len() >= 50,
        "only {} cases — the fixture shrank or stopped parsing",
        cases(&root).len()
    );
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
            .unwrap_or_else(|err| panic!("case {id}: the policy refused to evaluate it: {err}"));
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
        "{} of {} fixture cases disagree with the policy.\n\
         Either mls/core/src/rules.rs changed a decision — in which case every client \
         changed with it and the fixture is the record of that — or the fixture is wrong.\n{}",
        failures.len(),
        cases(&root).len(),
        failures.join("\n")
    );
}

#[test]
fn the_fixture_covers_every_sender_and_every_proposal_kind() {
    let root = fixture();

    // Only the plain `evaluate` cases count towards the grid, and only those
    // with the default `targetsSenderLeaf`, the default `byReference` and the
    // default rules: a cell covered solely by a configured, a not-my-leaf or a
    // by-reference variant is not the cell.
    let mut seen = BTreeSet::new();
    for case in cases(&root) {
        if case["call"] != "evaluate" || !case["rules"].is_null() {
            continue;
        }
        let proposal = &case["proposal"];
        if proposal["targetsSenderLeaf"].as_bool() == Some(false)
            || proposal["byReference"].as_bool() == Some(true)
        {
            continue;
        }
        if let (Some(sender), Some(kind)) = (proposal["sender"].as_str(), proposal["kind"].as_str())
        {
            seen.insert((sender.to_string(), kind.to_string()));
        }
    }

    let mut missing = Vec::new();
    for sender in SenderKind::ALL {
        for kind in ProposalKind::ALL {
            if !seen.contains(&(sender.name().to_string(), kind.name().to_string())) {
                missing.push(format!("{}/{}", sender.name(), kind.name()));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "mls/fixtures/rules.json has no case for {} of the {} sender×kind cells: {}\n\
         Write down what Peachy decides, with the reason, before shipping the variant.",
        missing.len(),
        SenderKind::ALL.len() * ProposalKind::ALL.len(),
        missing.join(", ")
    );
}

#[test]
fn every_deny_reason_is_reached_by_some_case() {
    let root = fixture();

    // The group-policy reasons (16 up, `peachy_mls_core::policy`) are reached
    // by `mls/fixtures/rosters.json`, which judges whole commits rather than
    // single proposals; the two tables together must reach every reason.
    let rosters: Value = serde_json::from_str(ROSTERS).expect("rosters.json is valid JSON");
    let reached: BTreeSet<&str> = cases(&root)
        .iter()
        .chain(cases(&rosters).iter())
        .filter_map(|case| case["expect"]["reason"].as_str())
        .collect();

    let missing: Vec<&str> = DenyReason::ALL
        .iter()
        .map(|reason| reason.name())
        .filter(|name| !reached.contains(name))
        .collect();

    assert!(
        missing.is_empty(),
        "no fixture case produces {missing:?}. A reason nothing reaches is a branch \
         this fixture cannot protect, and it can go wrong in one client with nothing going red."
    );

    // And the mirror: every reason a case NAMES is a real one. A typo in an
    // `expect` would otherwise be caught only indirectly, by the verdict
    // comparison, whose message is about a mismatch rather than about a name
    // that does not exist.
    for case in cases(&root) {
        if let Some(name) = case["expect"]["reason"].as_str() {
            let reason = DenyReason::from_name(name)
                .unwrap_or_else(|| panic!("no such deny reason: {name:?}"));
            assert_eq!(
                case["expect"]["reasonCode"].as_u64(),
                Some(u64::from(reason.code())),
                "case {}: reason {name:?} is code {}, not what the fixture says",
                case["id"],
                reason.code()
            );
        }
    }
}

#[test]
fn every_commit_sender_has_a_case() {
    let root = fixture();
    let seen: BTreeSet<&str> = cases(&root)
        .iter()
        .filter(|case| case["call"] == "evaluateCommitSender")
        .filter_map(|case| case["sender"].as_str())
        .collect();

    for sender in SenderKind::ALL {
        assert!(
            seen.contains(sender.name()),
            "no evaluateCommitSender case for {}. Who may commit is asked separately from \
             what the commit proposes, so it needs its own row per sender.",
            sender.name()
        );
    }
}
