// SPDX-License-Identifier: MIT
//! WHAT THE DELIVERY SERVICE CAN READ OFF A HANDSHAKE.
//!
//! Peachy's Delivery Service stores every commit verbatim
//! (the delivery service's stored commit bytes, the delivery service). It has never
//! deserialized one — it checks the epoch the CLIENT names, assigns a sequence
//! and writes the bytes — but "we do not look" is a promise about code, and
//! the code is ours to change. This file is the claim one layer down: the
//! bytes THEMSELVES do not carry it, so a copy of that table, a backup of it,
//! or a subpoena for it answers "who added whom" with nothing.
//!
//! Under OpenMLS' `MIXED_PLAINTEXT_WIRE_FORMAT_POLICY` they would: a commit
//! leaves as an RFC 9420 `PublicMessage`, whose `FramedContent` is in the
//! clear: the committer's leaf index, and — for an Add — the entire KeyPackage
//! of the person being added, `pdc1` credential and all.
//! `PEACHY_WIRE_FORMAT_POLICY` (`mls/core/src/group.rs`) frames handshakes as
//! `PrivateMessage` instead, under the epoch's own sender-data and handshake
//! keys, which no server ever holds.
//!
//! Every assertion of ABSENCE here is planted beside a control that proves the
//! search could have found something: the same needle is looked for in the
//! KeyPackage the adder was handed, where it really is present, with the same
//! function. An absence test whose needle was misspelled passes for ever.
//!
//! What remains readable is asserted too, in `what_the_service_still_reads`,
//! rather than left to the reader to infer from what is missing — see
//! docs/metadata.md §Encrypted handshakes for the honest list.

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use openmls::prelude::{
    tls_codec::Deserialize as _, ContentType, MlsMessageBodyIn, MlsMessageIn, WireFormat,
};
#[cfg(feature = "test-forgery")]
use openmls::prelude::{
    MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
    PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
};
use peachy_mls_core::Incoming;
use support::{client, credential_token, issuer};

const GROUP: &[u8] = b"peachy-group-opaque";

/// Does `haystack` contain `needle` anywhere?
///
/// Deliberately a plain byte scan rather than anything that understands MLS:
/// the question is what a person with the bytes and `grep` can find, not what
/// a parser will hand them.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    assert!(!needle.is_empty(), "an empty needle is in everything");
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The framing of one message, as the delivery service would see it: no keys,
/// no group state, nothing but the bytes off the wire.
fn framing(bytes: &[u8]) -> (WireFormat, ContentType) {
    let message =
        MlsMessageIn::tls_deserialize_exact(bytes).expect("the service can parse framing");
    let protocol = match message.extract() {
        MlsMessageBodyIn::PrivateMessage(m) => m.into(),
        MlsMessageBodyIn::PublicMessage(m) => m.into(),
        other => panic!("a handshake should be a group message, got {other:?}"),
    };
    let protocol: openmls::prelude::ProtocolMessage = protocol;
    (protocol.wire_format(), protocol.content_type())
}

/// AN ADD DOES NOT NAME WHO IT ADDS.
///
/// The `pdc1` token is the strongest possible needle: it is an ASCII string
/// beginning `pdc1.`, it contains the added person's actor id and the added
/// device's id, and under the old framing it travelled inside the commit
/// verbatim, as the added leaf's credential. If it is not in these bytes, no
/// weaker rendering of the same fact is either.
#[test]
fn a_delivery_service_cannot_read_who_a_commit_adds() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let mut cy = client(&server, 3, "actor-cy", "device-cy-phone");

    ada.create_group(GROUP).expect("create");
    let cy_kp = cy.generate_key_package().expect("cy key package");
    let seat_cy = ada.add_member(GROUP, &cy_kp).expect("add cy");
    ada.merge_pending_commit(GROUP).expect("merge");
    cy.join_from_welcome(&seat_cy.welcome.clone().expect("welcome"))
        .expect("cy joins");

    let bo_kp = bo.generate_key_package().expect("bo key package");
    let needle = credential_token(&server, 2, "actor-bo", "device-bo-phone");

    // THE CONTROL. The needle is really there to be found, in the bytes the
    // adder was handed — this is the same `contains`, the same needle, and it
    // must say yes.
    assert!(
        contains(&bo_kp, &needle),
        "the control failed: bo's credential is not even in his own key package, \
         so the absence below proves nothing",
    );
    assert!(
        contains(&bo_kp, b"pdc1."),
        "and it is readable as text, not merely present as bytes",
    );

    let add = ada.add_member(GROUP, &bo_kp).expect("add bo");

    // THE PROPERTY.
    assert!(
        !contains(&add.commit, &needle),
        "the commit that adds bo names bo",
    );
    assert!(
        !contains(&add.commit, b"pdc1."),
        "the commit carries a credential token of ANY kind in the clear",
    );
    assert_eq!(
        framing(&add.commit).0,
        WireFormat::PrivateMessage,
        "a handshake left this device in the clear",
    );

    // AND IT IS STILL A COMMIT THE GROUP CAN APPLY. An opaque handshake that
    // nobody can act on would pass every assertion above and be worthless.
    ada.merge_pending_commit(GROUP).expect("the adder merges");
    match cy
        .process_commit(GROUP, &add.commit)
        .expect("cy applies it")
    {
        Incoming::Commit(outcome) => assert_eq!(outcome.added.len(), 1, "cy saw the add"),
        other => panic!("expected a commit, got {other:?}"),
    }
    bo.join_from_welcome(&add.welcome.clone().expect("welcome"))
        .expect("and bo really joined");
    assert_eq!(
        bo.roster(GROUP).expect("roster").len(),
        3,
        "three leaves, from a commit the server could not read",
    );
}

/// A REMOVE DOES NOT NAME WHICH LEAF IT REMOVES — and the Welcome-less case is
/// the one that matters, because a Remove has no Welcome to blame it on.
///
/// A leaf index is four bytes and would turn up in any long buffer by chance,
/// so the assertion here is structural rather than a scan: the service is
/// handed the message it stores and gets a `PrivateMessage` back, which has no
/// `sender()` to ask and no proposal list to walk. Under the old framing the
/// same bytes gave a `PublicMessage`, and `PublicMessage::sender()` is a public
/// method of OpenMLS.
#[test]
fn a_delivery_service_cannot_read_which_leaf_a_commit_removes() {
    let server = issuer();
    let mut ada = client(&server, 4, "actor-ada", "device-ada-mac");
    let mut bo = client(&server, 5, "actor-bo", "device-bo-mac");
    let mut cy = client(&server, 6, "actor-cy", "device-cy-mac");

    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let seat_bo = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&seat_bo.welcome.clone().expect("welcome"))
        .expect("bo joins");

    let cy_kp = cy.generate_key_package().expect("cy key package");
    let seat_cy = ada.add_member(GROUP, &cy_kp).expect("add cy");
    ada.merge_pending_commit(GROUP).expect("merge");
    cy.join_from_welcome(&seat_cy.welcome.clone().expect("welcome"))
        .expect("cy joins");
    bo.process_commit(GROUP, &seat_cy.commit)
        .expect("bo follows");

    let cy_leaf = ada
        .roster(GROUP)
        .expect("roster")
        .into_iter()
        .find(|e| e.identity.as_ref().is_ok_and(|i| i.actor_id == "actor-cy"))
        .expect("cy is seated")
        .leaf_index;

    let evict = ada.remove_leaf(GROUP, cy_leaf).expect("remove cy");
    let message =
        MlsMessageIn::tls_deserialize_exact(&evict.commit).expect("the service parses framing");
    match message.extract() {
        MlsMessageBodyIn::PrivateMessage(_) => {}
        MlsMessageBodyIn::PublicMessage(public) => panic!(
            "the removal went out in the clear, sent by leaf {:?}",
            public.sender(),
        ),
        other => panic!("expected a group message, got {other:?}"),
    }
    // The needle control again, on the leaving member this time: Cy's own
    // credential is in the tree the group holds, and it is not in the commit
    // that empties his seat.
    let cy_token = credential_token(&server, 6, "actor-cy", "device-cy-mac");
    assert!(
        contains(&cy.generate_key_package().expect("kp"), &cy_token),
        "the control failed: cy's own credential is not in his own key package",
    );
    assert!(
        !contains(&evict.commit, &cy_token),
        "the commit that removes cy names cy",
    );
}

/// WHAT THE SERVICE STILL READS, said out loud.
///
/// `PrivateMessage` hides the content and the sender; it does not hide the
/// envelope. The group id is the routing key, the epoch is what `SubmitCommit`
/// checks its total order against, and the content type says a commit happened
/// rather than a message being sent. All three are asserted here so that this
/// file states the residue instead of implying there is none — the roadmap
/// item and every public surface say the same three things.
#[test]
fn what_the_service_still_reads() {
    let server = issuer();
    let mut ada = client(&server, 7, "actor-ada", "device-ada-ipad");
    let bo = client(&server, 8, "actor-bo", "device-bo-ipad");

    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let add = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");

    let message = MlsMessageIn::tls_deserialize_exact(&add.commit).expect("parse");
    let protocol: openmls::prelude::ProtocolMessage = match message.extract() {
        MlsMessageBodyIn::PrivateMessage(m) => m.into(),
        other => panic!("expected a private message, got {other:?}"),
    };
    assert_eq!(protocol.group_id().as_slice(), GROUP, "the routing key");
    assert_eq!(
        protocol.epoch().as_u64(),
        0,
        "the epoch it was built IN — a fresh group's first commit, not the one it produces",
    );
    assert_eq!(
        protocol.content_type(),
        ContentType::Commit,
        "that a commit happened, as against a message being sent",
    );

    // And the other side of the same coin: an application message is framed
    // identically apart from this byte, so the service cannot tell WHICH
    // handshake it is holding beyond "a commit" — no add, no remove, no count.
    let words = ada.encrypt(GROUP, b"hello").expect("encrypt");
    assert_eq!(
        framing(&words),
        (WireFormat::PrivateMessage, ContentType::Application)
    );
}

/// A STANDALONE PROPOSAL IS SEALED TOO.
///
/// Peachy's clients build no standalone proposals today — every membership
/// change is a commit — but the delivery service has a lane for them
/// (`MlsPayloadKind.PROPOSAL`) and the server takes them. The forge is the only
/// door in the core that produces one, which is why this test is gated the way
/// it is; the framing it checks is the same framing a real proposal would get,
/// because it comes from the same group config.
#[cfg(feature = "test-forgery")]
#[test]
fn a_standalone_proposal_is_sealed_too() {
    let server = issuer();
    let mut ada = client(&server, 9, "actor-ada", "device-ada-web");
    let bo = client(&server, 10, "actor-bo", "device-bo-web");

    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let add = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    let _ = add;

    let proposal = ada
        .forge_propose_self_update(GROUP)
        .expect("a standalone proposal");
    assert_eq!(
        framing(&proposal),
        (WireFormat::PrivateMessage, ContentType::Proposal),
        "a proposal left this device in the clear",
    );
}

/// AN EXISTING GROUP IS UPGRADED AT OPEN — the half that decides whether this
/// reaches anybody.
///
/// OpenMLS reads the join config it has in STORAGE, not the one
/// `join_config()` would build today, so a group created or joined by a build
/// that framed handshakes in the clear would have gone on doing it for ever.
/// The switch would then have reached new conversations only, and the
/// conversations people are in are the old ones — a change that looks shipped
/// and protects nobody.
///
/// The forge writes exactly the stored config such a store holds, so the
/// first half of this test also proves the FIXTURE is real: with that config
/// in place the commit genuinely comes out as a `PublicMessage` naming the
/// added device, which is the control for the assertion after the restart.
#[cfg(feature = "test-forgery")]
#[test]
fn a_group_stored_with_clear_handshakes_is_upgraded_when_it_is_next_opened() {
    use peachy_mls_core::{MemoryKv, PeachyStorage};

    let server = issuer();
    // A cloned `MemoryKv` is one map behind two handles, so this really is the
    // same store both times (`mls/core/tests/persistence.rs`).
    let kv = MemoryKv::new();

    let cy = client(&server, 13, "actor-cy", "device-cy-old");
    let cy_kp = cy.generate_key_package().expect("cy key package");
    let cy_token = credential_token(&server, 13, "actor-cy", "device-cy-old");

    // --- the fixture: a group whose store says plaintext handshakes ---------
    {
        let mut ada = support::client_on(
            &server,
            12,
            "actor-ada",
            "device-ada-old",
            PeachyStorage::open(Box::new(kv.clone())).expect("open the store"),
        );
        ada.create_group(GROUP).expect("create");
        ada.forge_stored_wire_format_policy(GROUP, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .expect("write the mixed stored config");

        // THE CONTROL. With that config the leak is real and this test can see
        // it — otherwise the assertion after the restart would pass whatever
        // `reopen_groups` did.
        let leaky = ada.add_member(GROUP, &cy_kp).expect("add cy");
        assert_eq!(
            framing(&leaky.commit).0,
            WireFormat::PublicMessage,
            "the fixture is not a fixture: the old config produced a sealed commit",
        );
        assert!(
            contains(&leaky.commit, &cy_token),
            "the fixture is not a fixture: a plaintext Add did not name the added device",
        );
        ada.clear_pending_commit(GROUP).expect("throw it away");
    }

    // --- the property: a fresh process over the same store ------------------
    let mut ada = support::client_on(
        &server,
        12,
        "actor-ada",
        "device-ada-old",
        PeachyStorage::open(Box::new(kv)).expect("reopen the store"),
    );
    let sealed = ada.add_member(GROUP, &cy_kp).expect("add cy again");
    assert_eq!(
        framing(&sealed.commit).0,
        WireFormat::PrivateMessage,
        "an existing group went on framing its handshakes in the clear after the upgrade",
    );
    assert!(
        !contains(&sealed.commit, &cy_token),
        "the upgraded group's commit still names the device it adds",
    );
}

/// A PLAINTEXT HANDSHAKE IS REFUSED, not processed.
///
/// Incoming handshakes are `AlwaysCiphertext`: there is no read path for a
/// `PublicMessage` commit (docs/metadata.md §Encrypted handshakes).
/// The forge
/// makes Ada a device that frames commits in the clear; the control
/// proves it really is a `PublicMessage`, and Bo — a current member at the
/// same epoch — must refuse it and stay where he was. Then the same change,
/// sealed, still applies: the refusal is about the framing, not the group.
#[cfg(feature = "test-forgery")]
#[test]
fn a_plaintext_handshake_is_refused() {
    let server = issuer();
    let mut ada = client(&server, 14, "actor-ada", "device-ada-refuse");
    let mut bo = client(&server, 15, "actor-bo", "device-bo-refuse");

    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let seat_bo = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&seat_bo.welcome.clone().expect("welcome"))
        .expect("bo joins");
    let epoch = bo.epoch(GROUP).expect("bo's epoch");

    ada.forge_stored_wire_format_policy(GROUP, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .expect("frame handshakes in the clear");
    let clear = ada.self_update(GROUP).expect("a plaintext commit");
    // THE CONTROL: without it, a refusal of a sealed commit for some other
    // reason would pass this test.
    assert_eq!(
        framing(&clear.commit),
        (WireFormat::PublicMessage, ContentType::Commit),
        "the fixture is not a fixture: the forged config produced a sealed commit",
    );

    let refused = bo.process_commit(GROUP, &clear.commit);
    assert!(
        refused.is_err(),
        "a plaintext commit was processed: {refused:?}",
    );
    assert!(
        format!("{:?}", refused.unwrap_err()).contains("wire format"),
        "refused, but not for its framing",
    );
    assert_eq!(
        bo.epoch(GROUP).expect("epoch"),
        epoch,
        "the refused commit moved bo"
    );

    // The same change, sealed, is still a commit bo applies.
    ada.clear_pending_commit(GROUP)
        .expect("throw the plaintext one away");
    ada.forge_stored_wire_format_policy(GROUP, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .expect("back to today's policy");
    let sealed = ada.self_update(GROUP).expect("a sealed commit");
    assert_eq!(framing(&sealed.commit).0, WireFormat::PrivateMessage);
    ada.merge_pending_commit(GROUP).expect("merge");
    match bo
        .process_commit(GROUP, &sealed.commit)
        .expect("bo applies the sealed one")
    {
        Incoming::Commit(_) => {}
        other => panic!("expected a commit, got {other:?}"),
    }
    assert_eq!(bo.epoch(GROUP).expect("epoch"), epoch + 1);
}

/// A GROUP STORED WITH MIXED INCOMING IS TIGHTENED AT OPEN — both halves of
/// the policy, not only the outgoing one.
///
/// For the day between sealing handshakes and dropping the plaintext read
/// path, groups were stored with `MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY`: sealed
/// out, either framing in. Their outgoing half already matches today's, so an
/// upgrade that compared only that half would leave every one of them
/// accepting plaintext for ever. The control is the same plaintext commit
/// processed by that stored config BEFORE the reopen, where it applies.
#[cfg(feature = "test-forgery")]
#[test]
fn a_group_stored_with_mixed_incoming_refuses_plaintext_after_it_is_reopened() {
    use peachy_mls_core::{MemoryKv, PeachyStorage};

    let server = issuer();
    let kv = MemoryKv::new();
    let open_bo = |kv: &MemoryKv| {
        support::client_on(
            &server,
            17,
            "actor-bo",
            "device-bo-mixed",
            PeachyStorage::open(Box::new(kv.clone())).expect("open the store"),
        )
    };

    let mut ada = client(&server, 16, "actor-ada", "device-ada-mixed");
    ada.create_group(GROUP).expect("create");
    let mut bo = open_bo(&kv);
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let seat_bo = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&seat_bo.welcome.clone().expect("welcome"))
        .expect("bo joins");
    bo.forge_stored_wire_format_policy(GROUP, MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .expect("write the stored config of the build that sealed outgoing only");

    ada.forge_stored_wire_format_policy(GROUP, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .expect("frame handshakes in the clear");
    let first = ada.self_update(GROUP).expect("a plaintext commit");
    ada.merge_pending_commit(GROUP).expect("merge");
    let second = ada.self_update(GROUP).expect("another plaintext commit");
    assert_eq!(framing(&second.commit).0, WireFormat::PublicMessage);

    // THE CONTROL: the mixed config really does accept plaintext.
    match bo
        .process_commit(GROUP, &first.commit)
        .expect("mixed incoming applies plaintext")
    {
        Incoming::Commit(_) => {}
        other => panic!("expected a commit, got {other:?}"),
    }
    let epoch = bo.epoch(GROUP).expect("epoch");

    // THE PROPERTY: a fresh process over the same store refuses it.
    drop(bo);
    let mut bo = open_bo(&kv);
    assert!(
        bo.process_commit(GROUP, &second.commit).is_err(),
        "a group stored with mixed incoming took plaintext after the upgrade",
    );
    assert_eq!(bo.epoch(GROUP).expect("epoch"), epoch);
}
