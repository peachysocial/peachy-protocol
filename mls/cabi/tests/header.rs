// SPDX-License-Identifier: MIT
//! The committed header must be what cbindgen produces from the source.
//!
//! `include/peachy_mls.h` is what a Swift or Kotlin wrapper is written against,
//! and it is committed so that reading it needs no Rust toolchain. That only
//! works if it cannot silently fall behind `src/lib.rs`, which is this test.

#[test]
fn the_committed_header_matches_the_source() {
    let generated_path = env!("PEACHY_MLS_GENERATED_HEADER");
    if generated_path.is_empty() {
        // build.rs prints a cargo:warning in this case and does not fail the
        // build, because a header that will not generate must not stop the
        // library compiling. Skipping here rather than failing keeps that
        // promise; the warning is the signal.
        eprintln!("cbindgen did not run; skipping the header drift check");
        return;
    }

    let generated = std::fs::read_to_string(generated_path)
        .unwrap_or_else(|err| panic!("the generated header should be readable: {err}"));
    let committed = include_str!("../include/peachy_mls.h");

    // The generated header lives under Cargo's OUT_DIR, whose path only the
    // build knows, so the message spells the copy command out with it.
    assert_eq!(
        committed, generated,
        "\ninclude/peachy_mls.h has drifted from src/lib.rs. Refresh it, from mls/, with:\n\
         \n    cp \"{generated_path}\" cabi/include/peachy_mls.h\n"
    );
}

#[test]
fn the_header_declares_every_entry_point() {
    let committed = include_str!("../include/peachy_mls.h");
    // A spelled-out list, not a derivation: the point is to notice a function
    // that was added to the ABI and never reached the header, and a list
    // generated from the same source cannot notice that.
    for symbol in [
        "peachy_mls_last_error",
        "peachy_mls_version",
        "peachy_mls_abi_version",
        "peachy_mls_set_server_clock_offset_ms",
        "peachy_mls_server_clock_offset_ms",
        "peachy_mls_server_key_pin_report",
        "peachy_mls_server_keys_pinned",
        "peachy_mls_buffer_free",
        "peachy_mls_client_new",
        "peachy_mls_client_open",
        "peachy_mls_client_open_existing",
        "peachy_mls_store_encrypt_in_place",
        "peachy_mls_client_free",
        "peachy_mls_client_identity",
        "peachy_mls_key_package",
        // The device-link door: unconditional, unlike the two feature-gated
        // ones below, because approving a second device is product code in
        // three apps.
        "peachy_mls_device_approval_statement",
        "peachy_mls_sign_device_approval",
        "peachy_mls_verify_device_approval",
        "peachy_mls_device_link_commitment",
        "peachy_mls_device_link_number",
        "peachy_mls_device_link_approver_number",
        "peachy_mls_device_link_qr",
        "peachy_mls_device_link_qr_matches",
        "peachy_mls_device_link_qr_secret",
        "peachy_mls_device_link_waiter_step",
        "peachy_mls_sign_device_link_commitment",
        "peachy_mls_verify_device_link_commitment",
        "peachy_mls_device_link_approver_step",
        "peachy_mls_generate_device_link_kem_seed",
        "peachy_mls_device_link_kem_public_key",
        "peachy_mls_sign_device_link_kem",
        "peachy_mls_verify_device_link_kem",
        "peachy_mls_account_identity_public_key",
        "peachy_mls_sign_account_device",
        "peachy_mls_verify_account_device",
        "peachy_mls_client_account_key",
        "peachy_mls_group_observe_account_keys",
        // The account store: unconditional too.
        "peachy_mls_generate_account_key",
        "peachy_mls_account_key_seal",
        "peachy_mls_account_key_seal_hybrid",
        "peachy_mls_account_key_accept_hybrid",
        "peachy_mls_account_key_open",
        "peachy_mls_transfer_key_seal",
        "peachy_mls_transfer_key_open",
        "peachy_mls_store_seal",
        "peachy_mls_store_open",
        "peachy_mls_note_seal_signed",
        "peachy_mls_note_sender",
        "peachy_mls_note_open_signed",
        "peachy_mls_group_create",
        "peachy_mls_group_join",
        "peachy_mls_group_contested_welcome_id",
        "peachy_mls_group_join_contested_welcome",
        "peachy_mls_group_welcome_group",
        "peachy_mls_group_join_at_head",
        "peachy_mls_group_join_at_head_logged",
        "peachy_mls_group_confirm_head",
        "peachy_mls_group_head_rolled_back",
        "peachy_mls_group_last_head_read",
        "peachy_mls_group_note_head_read",
        "peachy_mls_group_recovery_begin",
        "peachy_mls_group_recovery_judge",
        "peachy_mls_group_recovery_read_due",
        "peachy_mls_recovery_drain_complete",
        "peachy_mls_first_sight_of_join_request",
        "peachy_mls_join_request_seen",
        "peachy_mls_group_add_member",
        "peachy_mls_group_add_member_for_ask",
        "peachy_mls_group_seat_founding",
        "peachy_mls_group_founding_refusals",
        "peachy_mls_founding_seats",
        "peachy_mls_group_remove_member",
        "peachy_mls_group_remove_stale_leaf",
        "peachy_mls_group_process_mailbox_entry",
        "peachy_mls_envelope_door",
        "peachy_mls_group_propose_leave",
        "peachy_mls_group_commit_proposed_leaves",
        "peachy_mls_group_begin_leave",
        "peachy_mls_group_is_leaving",
        "peachy_mls_group_follow_leave",
        "peachy_mls_group_leave_recipients",
        "peachy_mls_group_replace_member",
        "peachy_mls_group_reseat_person",
        "peachy_mls_note_own_install_links",
        "peachy_mls_sign_install_revocations",
        "peachy_mls_group_is_behind",
        "peachy_mls_group_commit_strands",
        "peachy_mls_group_forget",
        "peachy_mls_group_forget_remembered_roster",
        "peachy_mls_group_take_rejoin_report",
        "peachy_mls_group_peek_rejoin_report",
        "peachy_mls_group_drop_rejoin_report",
        "peachy_mls_group_self_update",
        "peachy_mls_client_update_credential",
        "peachy_mls_group_own_leaf_credential_expires_at",
        "peachy_mls_group_leaf_credential_expiring",
        "peachy_mls_group_leaf_credential_past_grace",
        "peachy_mls_group_credential_refresh_due",
        "peachy_mls_group_refresh_credential",
        "peachy_mls_group_merge_pending_commit",
        "peachy_mls_group_clear_pending_commit",
        "peachy_mls_group_has_pending_commit",
        "peachy_mls_group_has_saved_commit",
        "peachy_mls_group_settle_saved_commit",
        "peachy_mls_group_member_count",
        "peachy_mls_group_member",
        "peachy_mls_group_member_account_key",
        "peachy_mls_key_package_identity",
        "peachy_mls_key_package_account_key",
        "peachy_mls_check_own_device_approval",
        "peachy_mls_check_own_device_key",
        "peachy_mls_remember_own_approver",
        "peachy_mls_forget_own_device",
        "peachy_mls_own_sibling_leaves",
        "peachy_mls_own_device_trust",
        "peachy_mls_adopt_own_device_trust",
        "peachy_mls_client_adopt_refusals",
        "peachy_mls_own_device_standing",
        "peachy_mls_group_epoch",
        "peachy_mls_group_encrypt",
        "peachy_mls_group_encrypt_with_hint",
        "peachy_mls_peek_message",
        "peachy_mls_group_process_door",
        "peachy_mls_group_process_message_as",
        "peachy_mls_release_opened",
        "peachy_mls_release_opened_all",
        "peachy_mls_incoming_free",
        "peachy_mls_group_export_secret",
        "peachy_mls_group_export_pending_secret",
        "peachy_mls_group_typing_seal",
        "peachy_mls_group_typing_open",
        "peachy_mls_peek_commitment",
        "peachy_mls_resend_author_commitment",
    ] {
        assert!(
            committed.contains(symbol),
            "{symbol} is missing from include/peachy_mls.h"
        );
    }
    assert!(committed.contains("#ifndef PEACHY_MLS_H"));
    assert!(committed.contains("typedef struct PeachyMlsClient PeachyMlsClient;"));
}

/// There is no doorless way into the engine. Every incoming group message
/// goes through `peachy_mls_group_process_door`, which refuses a commit on the
/// message door, an application message on the commit door and a proposal on
/// either before the engine reads it. A doorless entry point would merge a
/// commit that arrived as a message, off the commit path, and the drift check
/// alone would let one come back as long as the header followed it.
#[test]
fn the_header_has_no_doorless_process() {
    let committed = include_str!("../include/peachy_mls.h");
    assert!(
        !committed.contains("peachy_mls_group_process("),
        "include/peachy_mls.h declares a doorless peachy_mls_group_process"
    );
    assert!(committed.contains("int32_t peachy_mls_group_process_door("));
}

/// A roster leaf hands back its signing key, and the header says so.
///
/// A name-only list cannot notice a parameter, and this one is load-bearing:
/// it is how a wrapper reads the key of a device already in the group, the
/// kind of key `peachy_mls_check_own_device_approval` checks an approval
/// against (the core reads it from the tree itself). A key taken from the
/// directory instead would be one the directory chose, and that is a silent
/// weakening, not a compile error, which is why it is asserted here rather
/// than left to the drift check alone.
#[test]
fn a_roster_leaf_hands_back_its_signing_key() {
    let committed = include_str!("../include/peachy_mls.h");
    let declaration = committed
        .split("int32_t peachy_mls_group_member(")
        .nth(1)
        .and_then(|rest| rest.split(");").next())
        .expect("the header declares peachy_mls_group_member");
    assert!(
        declaration.contains("PeachyMlsBuffer *out_device_key"),
        "peachy_mls_group_member must hand back the leaf's signing key; \
         it declares:\n{declaration}"
    );
}

/// The `test-issuer` door is in the committed header whether or not this build
/// turned the feature on, wrapped in a preprocessor guard.
///
/// That is the whole reason `cbindgen.toml` maps the cargo feature to a C
/// define: one header describes both builds, so the drift test above holds
/// under `cargo test` and under `cargo test --all-features` alike. Two
/// committed headers would have meant one of them was always the stale one.
#[test]
fn the_test_issuer_door_is_present_but_guarded() {
    let committed = include_str!("../include/peachy_mls.h");
    for symbol in [
        "peachy_mls_test_issuer_new",
        "peachy_mls_test_issuer_free",
        "peachy_mls_test_issuer_published_keys",
        "peachy_mls_test_issuer_issue",
        "typedef struct PeachyMlsTestIssuer PeachyMlsTestIssuer;",
    ] {
        assert!(
            committed.contains(symbol),
            "{symbol} is missing from include/peachy_mls.h"
        );
    }
    assert!(
        committed.contains("#if defined(PEACHY_MLS_TEST_ISSUER)"),
        "the issuer door must be behind a preprocessor guard, \
         or a release consumer of this header would declare functions \
         that are not in the library"
    );
    // The guard count and the `#endif` count for it must agree, or a plain
    // build's compiler would see a declaration it has no symbol for.
    assert_eq!(
        committed
            .matches("#if defined(PEACHY_MLS_TEST_ISSUER)")
            .count(),
        5,
        "one guard for the opaque type and one per entry point"
    );
}

/// The golden-fixture door, the second feature-gated one, on the same terms.
///
/// Its own test rather than a line added above, because the thing worth
/// noticing is that the header now describes THREE builds — neither feature,
/// one, or both — off one committed file. A second define that nobody guarded
/// would declare a function a plain build has no symbol for, and the failure
/// would arrive in whichever wrapper linked it rather than here.
#[test]
fn the_fixture_door_is_present_but_guarded() {
    let committed = include_str!("../include/peachy_mls.h");
    assert!(
        committed.contains("peachy_mls_fixture_evaluate_case"),
        "peachy_mls_fixture_evaluate_case is missing from include/peachy_mls.h; \
         the Swift and Kotlin replays of mls/fixtures/rules.json are written against it"
    );
    assert_eq!(
        committed.matches("#if defined(PEACHY_MLS_FIXTURE)").count(),
        1,
        "one guard, for the one entry point the fixture door has"
    );
    // The two features are independent: a build may have either, both or
    // neither, so neither guard may be nested inside the other.
    assert!(
        !committed.contains("#if defined(PEACHY_MLS_TEST_ISSUER)\n#if defined(PEACHY_MLS_FIXTURE)"),
        "the two feature guards must not nest: `fixture` does not imply `test-issuer`"
    );
}
