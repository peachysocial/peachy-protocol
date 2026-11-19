// SPDX-License-Identifier: MIT
//! A GROUP'S NAME AND PHOTO, CARRIED IN ITS OWN STATE.
//!
//! `mls/core/src/group_meta.rs` says why the name is a GroupContext extension
//! (docs/sealed-messages.md §The name is in the group). This
//! file holds the two claims that decision rests on, over the real wire bytes:
//!
//! 1. **The commit that sets it does not carry it readably.** The delivery
//!    service stores every commit verbatim (the delivery service's stored commit bytes); a
//!    rename whose bytes contain the name would be a rename the server can
//!    read. Planted beside a CONTROL that proves the scan can see it: the same
//!    commit built under the plaintext-handshake policy builds used before
//!    handshakes were sealed DOES contain the name, found by the same function.
//! 2. **A member added later learns it from the Welcome, which does not carry
//!    it readably either.** The server routes Welcomes verbatim too.
//!
//! And the parts that make it usable: any member may rename (it is not an
//! admin act), a second rename replaces the first, and a leaf seated before
//! the extension existed is renewed by the path every client already runs.

mod support;

use openmls::prelude::MIXED_PLAINTEXT_WIRE_FORMAT_POLICY;
use peachy_mls_core::{DenyReason, Error, Incoming};
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-group-meta";

/// The value every client's codec writes (mls/fixtures/formats/group-meta.json).
const NAMED: &[u8] = "{\"v\":1,\"n\":\"Alice's cardiology results\"}".as_bytes();
const NEEDLE: &[u8] = b"cardiology";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    assert!(!needle.is_empty(), "an empty needle is in everything");
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn two_member_group() -> (peachy_mls_core::Client, peachy_mls_core::Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let added = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge the add");
    bo.join_from_welcome(&added.welcome.expect("welcome"))
        .expect("bo joins");
    (ada, bo)
}

#[test]
fn a_new_group_has_no_meta_and_costs_nothing() {
    let (ada, bo) = two_member_group();
    assert_eq!(ada.group_meta(GROUP).expect("meta"), None);
    assert_eq!(bo.group_meta(GROUP).expect("meta"), None);
    assert!(!ada.leaf_capabilities_stale(GROUP).expect("caps"));
    assert!(!bo.leaf_capabilities_stale(GROUP).expect("caps"));
}

#[test]
fn a_rename_reaches_the_other_member_and_its_bytes_do_not_carry_the_name() {
    let (mut ada, mut bo) = two_member_group();

    let bundle = ada
        .set_group_meta(GROUP, NAMED)
        .expect("any member may rename");
    assert!(bundle.welcome.is_none(), "a rename invites nobody");
    assert!(
        !contains(&bundle.commit, NEEDLE),
        "the rename commit carries the name where the delivery service can read it"
    );
    // Staged, not merged.
    assert_eq!(ada.group_meta(GROUP).expect("meta"), None);
    ada.merge_pending_commit(GROUP).expect("merge");
    assert_eq!(ada.group_meta(GROUP).expect("meta").as_deref(), Some(NAMED));

    match bo
        .process_commit(GROUP, &bundle.commit)
        .expect("bo processes it")
    {
        Incoming::Commit(outcome) => {
            assert_eq!(outcome.sender.actor_id, "actor-ada");
        }
        other => panic!("expected a commit, got {other:?}"),
    }
    assert_eq!(bo.group_meta(GROUP).expect("meta").as_deref(), Some(NAMED));
}

#[test]
fn the_control_a_plaintext_handshake_would_have_carried_the_name() {
    // Without this, the absence above could be a scan that finds nothing.
    let (mut ada, _bo) = two_member_group();
    ada.forge_stored_wire_format_policy(GROUP, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .expect("a plaintext-handshake wire format policy");
    let leaky = ada.set_group_meta(GROUP, NAMED).expect("rename");
    assert!(
        contains(&leaky.commit, NEEDLE),
        "the fixture is not a fixture: a plaintext GroupContextExtensions commit did not carry the name"
    );
    ada.clear_pending_commit(GROUP).expect("throw it away");
}

#[test]
fn a_member_added_later_reads_the_name_from_a_welcome_that_does_not_carry_it() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut cy = client(&server, 3, "actor-cy", "device-cy-phone");
    ada.create_group(GROUP).expect("create");
    ada.set_group_meta(GROUP, NAMED).expect("name it");
    ada.merge_pending_commit(GROUP).expect("merge");

    let cy_kp = cy.generate_key_package().expect("cy key package");
    let seat = ada.add_member(GROUP, &cy_kp).expect("add cy");
    let welcome = seat.welcome.expect("welcome");
    assert!(
        !contains(&welcome, NEEDLE),
        "the Welcome carries the group's name where the delivery service can read it"
    );
    assert!(!contains(&seat.commit, NEEDLE));
    ada.merge_pending_commit(GROUP).expect("merge");
    cy.join_from_welcome(&welcome).expect("cy joins");
    // Nobody re-sent anything: the name is in the state Cy joined.
    assert_eq!(cy.group_meta(GROUP).expect("meta").as_deref(), Some(NAMED));
}

/// A topic (docs/sealed-messages.md §The value): the same value, key `t`.
const WITH_TOPIC: &[u8] =
    "{\"v\":1,\"n\":\"\",\"t\":\"Planning the oncology referral\"}".as_bytes();
const TOPIC_NEEDLE: &[u8] = b"oncology";

#[test]
fn a_topic_rides_the_commit_and_the_welcome_where_the_delivery_service_cannot_read_it() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let mut cy = client(&server, 3, "actor-cy", "device-cy-phone");
    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let added = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge the add");
    bo.join_from_welcome(&added.welcome.expect("welcome"))
        .expect("bo joins");

    let set = ada.set_group_meta(GROUP, WITH_TOPIC).expect("set a topic");
    assert!(
        !contains(&set.commit, TOPIC_NEEDLE),
        "the topic commit carries the topic where the delivery service can read it"
    );
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &set.commit)
        .expect("bo processes it");
    assert_eq!(
        bo.group_meta(GROUP).expect("meta").as_deref(),
        Some(WITH_TOPIC)
    );

    let cy_kp = cy.generate_key_package().expect("cy key package");
    let seat = ada.add_member(GROUP, &cy_kp).expect("add cy");
    let welcome = seat.welcome.expect("welcome");
    assert!(
        !contains(&welcome, TOPIC_NEEDLE),
        "the Welcome carries the topic in the clear"
    );
    assert!(!contains(&seat.commit, TOPIC_NEEDLE));
    ada.merge_pending_commit(GROUP).expect("merge");
    cy.join_from_welcome(&welcome).expect("cy joins");
    assert_eq!(
        cy.group_meta(GROUP).expect("meta").as_deref(),
        Some(WITH_TOPIC)
    );
}

#[test]
fn the_control_a_plaintext_handshake_would_have_carried_the_topic() {
    let (mut ada, _bo) = two_member_group();
    ada.forge_stored_wire_format_policy(GROUP, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .expect("a plaintext-handshake wire format policy");
    let leaky = ada.set_group_meta(GROUP, WITH_TOPIC).expect("set a topic");
    assert!(
        contains(&leaky.commit, TOPIC_NEEDLE),
        "the fixture is not a fixture: a plaintext commit did not carry the topic"
    );
    ada.clear_pending_commit(GROUP).expect("throw it away");
}

#[test]
fn the_longest_name_and_topic_fit_the_cap() {
    // 100 four-byte scalars of name, 1,000 bytes of topic and a photo
    // pointer, with the JSON around them, fit MAX_GROUP_META_BYTES — the
    // arithmetic the 16,384-byte cap rests on (the topic is capped in BYTES
    // for exactly this).
    let name = "\u{1F351}".repeat(100);
    let topic = "\u{1F351}".repeat(250);
    let value = format!(
        "{{\"v\":1,\"n\":\"{name}\",\"t\":\"{topic}\",\"a\":{}}}",
        worst_photo()
    );
    assert!(value.len() <= peachy_mls_core::group_meta::MAX_GROUP_META_BYTES);
    let (mut ada, _bo) = two_member_group();
    ada.set_group_meta(GROUP, value.as_bytes()).expect("fits");
}

/// A photo pointer with all nine of its keys at their longest
/// (mls/fixtures/formats/group-meta.json, `a`).
fn worst_photo() -> serde_json::Value {
    serde_json::json!({
        "v": 3,
        "o": "sealed-meta/0f8e2a1c-5b7d-4e9a-8c3f-2d1b6a9e7c40.bin",
        "k": "q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=",
        "n": "AQIDBA==",
        "d": "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "s": 5_000_000,
        "m": "image/jpeg",
        "cs": 65_536,
        "x": "q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA",
    })
}

#[test]
fn a_policy_groups_state_at_every_cap_at_once_fits_the_cap() {
    // What MAX_GROUP_META_BYTES says it holds at its worst, written as a
    // client's codec writes it (serde_json escapes as every client's does):
    // the longest name; a topic at both of its caps with as many characters
    // as possible that JSON escapes; the photo; MAX_ADMINS admins and
    // MAX_BANNED bans, all distinct; every policy key; the group link; the
    // timer at its longest; Advanced Chat Privacy; and an event chat's tag.
    let uuid = |i: usize| format!("{i:08x}-0000-4000-8000-000000000000");
    let name = "\u{1F351}".repeat(100);
    // x quotes and y four-byte scalars: x + y <= 500 scalars, x + 4y <= 1000
    // bytes; escaped, 2x + 4y is largest at y = 166.
    let topic = format!("{}{}", "\u{1F351}".repeat(166), "\"".repeat(334));
    assert!(topic.chars().count() <= 500 && topic.len() <= 1000);
    let admins: Vec<String> = (0..peachy_mls_core::policy::MAX_ADMINS).map(uuid).collect();
    let banned: Vec<String> = (0..peachy_mls_core::policy::MAX_BANNED)
        .map(|i| uuid(1_000 + i))
        .collect();
    let value = serde_json::json!({
        "v": 1,
        "n": name,
        "t": topic,
        "a": worst_photo(),
        "acp": true,
        "adm": admins,
        "pol": {"add": "adm", "meta": "adm", "acp": "adm", "rm": "any"},
        "lk": {"k": "AAECAwQFBgcICQoLDA0ODw", "r": "EBESExQVFhcYGRobHB0eHw", "a": "adm"},
        "ban": banned,
        "dis": 2_419_200,
        "ev": {"i": uuid(9_999), "k": "ICEiIyQlJicoKSorLC0uLw"},
    })
    .to_string();
    assert!(
        value.len() <= peachy_mls_core::group_meta::MAX_GROUP_META_BYTES,
        "the worst case is {} bytes",
        value.len()
    );
    peachy_mls_core::group_meta::check_group_meta_value(value.as_bytes())
        .expect("the core takes the worst case");
}

#[test]
fn any_member_may_rename_and_a_second_rename_replaces_the_first() {
    let (mut ada, mut bo) = two_member_group();
    let first = ada.set_group_meta(GROUP, NAMED).expect("ada renames");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &first.commit)
        .expect("bo processes it");

    // Bo, who created nothing, renames too.
    let second_value = "{\"v\":1,\"n\":\"Results\"}".as_bytes();
    let second = bo
        .set_group_meta(GROUP, second_value)
        .expect("a plain member renames");
    bo.merge_pending_commit(GROUP).expect("merge");
    ada.process_commit(GROUP, &second.commit)
        .expect("ada accepts a rename from a plain member");
    for member in [&ada, &bo] {
        assert_eq!(
            member.group_meta(GROUP).expect("meta").as_deref(),
            Some(second_value)
        );
    }
}

#[test]
fn an_empty_or_oversized_value_is_refused_before_any_commit() {
    let (mut ada, _bo) = two_member_group();
    assert!(matches!(
        ada.set_group_meta(GROUP, b""),
        Err(Error::InvalidArgument(_))
    ));
    let huge = vec![b'x'; peachy_mls_core::MAX_GROUP_META_BYTES + 1];
    assert!(matches!(
        ada.set_group_meta(GROUP, &huge),
        Err(Error::InvalidArgument(_))
    ));
    assert!(!ada.has_pending_commit(GROUP).expect("pending"));
}

#[test]
fn the_policy_lets_a_rename_through_and_nothing_riding_with_it() {
    use peachy_mls_core::rules::{PeachyMlsRules, PolicyDecision, ProposalContext, ProposalKind};
    let rules = PeachyMlsRules::default();
    let rename = ProposalContext {
        sets_group_meta: true,
        ..ProposalContext::from_member(ProposalKind::GroupContextExtensions)
    };
    assert_eq!(rules.evaluate(&rename), PolicyDecision::Allow);
    let neither = ProposalContext::from_member(ProposalKind::GroupContextExtensions);
    assert_eq!(
        rules.evaluate(&neither),
        PolicyDecision::Deny(DenyReason::GroupContextExtensionsUnsupported)
    );
}
