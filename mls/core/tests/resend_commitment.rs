// SPDX-License-Identifier: MIT
//! A resendable message commits to its author where a receiver that cannot
//! open it can read the commitment (docs/sealed-messages.md
//! §Asking for a message again).
//!
//! 1. A transcript message's peek carries the commitment to its sender and
//!    its own `i`; no other member, and no other `i`, matches it.
//! 2. A salted lane frame commits to its sender and its whole text; an
//!    unsalted one, and every other hint, commit to nobody.
//! 3. The commitment costs no length tell: every hint's authenticated data
//!    is one length, so equal plaintexts make equal messages.
//! 4. The message still opens, and an older reader still reads its hint.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::hint::{
    peek_message, resend_author_commitment, CONTENT_HINT_DEFAULT, CONTENT_HINT_IMPLICIT,
    CONTENT_HINT_RESENDABLE, CONTENT_HINT_RESENDABLE_LANE,
};
use peachy_mls_core::{Client, Incoming};
use support::{client, issuer};

const G: &[u8] = b"0f8e2a1c-5b7d-4e9a-8c3f-2d1b6a9e7c40";
const ADA: &str = "5b0f5a52-8a55-4a5b-9d59-1b9a7a3f0c11";
const BO: &str = "0f3c6d2e-1111-4222-8333-944455556666";
const ID: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

fn pair() -> (Client, Client) {
    let s = issuer();
    let mut ada = client(&s, 1, ADA, "11111111-aaaa-4aaa-8aaa-111111111111");
    let mut bo = client(&s, 2, BO, "22222222-bbbb-4bbb-8bbb-222222222222");
    ada.create_group(G).unwrap();
    let kp = bo.generate_key_package().unwrap();
    let added = ada.add_member(G, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.join_from_welcome(&added.welcome.unwrap()).unwrap();
    (ada, bo)
}

fn transcript(id: &str) -> Vec<u8> {
    let mut frame = vec![0xFF, 0x05];
    frame.extend_from_slice(format!(r#"{{"i":"{id}","t":"see you at eight","a":[]}}"#).as_bytes());
    frame
}

#[test]
fn a_transcript_message_commits_to_its_sender() {
    let (mut ada, mut bo) = pair();
    let pt = transcript(ID);
    let mls = ada
        .encrypt_with_hint(G, &pt, CONTENT_HINT_RESENDABLE)
        .unwrap();
    let peek = peek_message(&mls).unwrap();
    assert_eq!(peek.hint, Some(CONTENT_HINT_RESENDABLE));
    let commitment = peek.commitment.expect("a commitment");
    assert_eq!(commitment, resend_author_commitment(G, ADA, ID.as_bytes()));
    assert_ne!(commitment, resend_author_commitment(G, BO, ID.as_bytes()));
    assert_ne!(
        commitment,
        resend_author_commitment(G, ADA, b"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4e")
    );
    // Bo's answer for the same frame (what a member forging it would send)
    // commits to Bo, not to Ada.
    let forged = bo
        .encrypt_with_hint(G, &pt, CONTENT_HINT_RESENDABLE)
        .unwrap();
    assert_ne!(peek_message(&forged).unwrap().commitment, Some(commitment));
    match bo.process_message(G, &mls).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, pt),
        other => panic!("expected an application message, got {other:?}"),
    }
    // An upper-case id commits as its lower-case self.
    let upper = transcript(&ID.to_ascii_uppercase());
    let mls = ada
        .encrypt_with_hint(G, &upper, CONTENT_HINT_RESENDABLE)
        .unwrap();
    assert_eq!(peek_message(&mls).unwrap().commitment, Some(commitment));
}

#[test]
fn a_salted_lane_frame_commits_and_an_unsalted_one_does_not() {
    let (mut ada, _bo) = pair();
    let salted = format!(r#"{{"peachy":"del","v":1,"m":"{ID}","z":"AAECAwQFBgcICQoLDA0ODw=="}}"#);
    let mls = ada
        .encrypt_with_hint(G, salted.as_bytes(), CONTENT_HINT_RESENDABLE_LANE)
        .unwrap();
    assert_eq!(
        peek_message(&mls).unwrap().commitment,
        Some(resend_author_commitment(G, ADA, salted.as_bytes()))
    );
    let unsalted = format!(r#"{{"peachy":"del","v":1,"m":"{ID}"}}"#);
    let mls = ada
        .encrypt_with_hint(G, unsalted.as_bytes(), CONTENT_HINT_RESENDABLE_LANE)
        .unwrap();
    assert_eq!(peek_message(&mls).unwrap().commitment, None);
    for hint in [CONTENT_HINT_DEFAULT, CONTENT_HINT_IMPLICIT] {
        let mls = ada.encrypt_with_hint(G, &transcript(ID), hint).unwrap();
        assert_eq!(peek_message(&mls).unwrap().commitment, None, "hint {hint}");
    }
}

#[test]
fn every_hint_is_one_length() {
    let (mut ada, _bo) = pair();
    let pt = transcript(ID);
    let lengths: Vec<usize> = [
        CONTENT_HINT_DEFAULT,
        CONTENT_HINT_RESENDABLE,
        CONTENT_HINT_IMPLICIT,
        CONTENT_HINT_RESENDABLE_LANE,
    ]
    .into_iter()
    .map(|hint| ada.encrypt_with_hint(G, &pt, hint).unwrap().len())
    .collect();
    assert!(lengths.windows(2).all(|w| w[0] == w[1]), "{lengths:?}");
}

/// 5. The golden table (`mls/fixtures/formats/resend.json`
///    `commitmentCases`), replayed through the fixture door, so the rule the
///    three clients reach through the core is pinned byte for byte.
#[test]
fn every_commitment_case_gets_the_verdict_it_expects() {
    let root: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/formats/resend.json"))
            .expect("resend.json is valid JSON");
    let cases = root["commitmentCases"]
        .as_array()
        .expect("`commitmentCases` is an array");
    assert!(cases.len() >= 10, "only {} commitment cases", cases.len());
    let mut failures = Vec::new();
    for case in cases {
        assert_eq!(case["kind"], "resend_commitment", "case {}", case["name"]);
        let actual = peachy_mls_core::fixture::evaluate_case_json(&case.to_string())
            .unwrap_or_else(|err| panic!("case {}: the door refused it: {err}", case["name"]));
        let actual: serde_json::Value = serde_json::from_str(&actual).unwrap();
        if actual != case["expect"] {
            failures.push(format!(
                "  {}\n    expected {}\n    actual   {actual}",
                case["name"], case["expect"]
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
