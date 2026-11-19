// SPDX-License-Identifier: MIT
//! The basic group journey (create, join, send, add, remove, update), with
//! the identity and policy layers in the path.
//!
//! Three members, because someone has to still be there to receive after the
//! removal — a two-member group where one leaves has nobody left to prove the
//! removal worked.

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::{Error, Incoming};
use support::{client, issuer, NOW};

const GROUP: &[u8] = b"peachy-group-e2e";

#[test]
fn two_members_create_add_talk_both_ways_remove_and_the_removed_cannot_read() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let mut cy = client(&server, 3, "actor-cy", "device-cy-phone");

    // --- create -----------------------------------------------------------
    ada.create_group(GROUP).expect("create");
    assert_eq!(ada.epoch(GROUP).expect("epoch"), 0);
    assert_eq!(ada.roster(GROUP).expect("roster").len(), 1);

    // --- add Bo via KeyPackage + Welcome ----------------------------------
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let added_bo = ada.add_member(GROUP, &bo_kp).expect("add bo");
    // Staged, not merged: Ada is still at epoch 0 until the delivery service
    // has taken the commit (mls/core/src/group.rs §The commit lifecycle).
    assert_eq!(ada.epoch(GROUP).expect("epoch"), 0);
    assert_eq!(added_bo.epoch, 1, "the bundle names the epoch it produces");
    assert!(ada.has_pending_commit(GROUP).expect("pending"));
    assert_eq!(ada.merge_pending_commit(GROUP).expect("merge"), 1);
    assert!(!ada.has_pending_commit(GROUP).expect("pending"));
    let welcome = added_bo.welcome.clone().expect("adding produces a Welcome");
    let joined = bo.join_from_welcome(&welcome).expect("bo joins");
    assert_eq!(joined, GROUP);
    assert_eq!(bo.epoch(GROUP).expect("epoch"), 1);
    assert_eq!(ada.epoch(GROUP).expect("epoch"), 1);

    // Bo's view of the roster identifies Ada by her actor id, which is the
    // whole point of the credential: the tree alone would only say "a leaf
    // holding this key".
    let roster = bo.roster(GROUP).expect("roster");
    assert_eq!(roster.len(), 2);
    let mut actors: Vec<String> = roster
        .iter()
        .map(|entry| {
            entry
                .identity
                .as_ref()
                .expect("every leaf verifies")
                .actor_id
                .clone()
        })
        .collect();
    actors.sort();
    assert_eq!(actors, vec!["actor-ada", "actor-bo"]);

    // --- add Cy, so there is a witness to the removal ---------------------
    let cy_kp = cy.generate_key_package().expect("cy key package");
    let added_cy = ada.add_member(GROUP, &cy_kp).expect("add cy");
    ada.merge_pending_commit(GROUP).expect("merge the add");
    // Bo learns about Cy from the commit; Cy learns from the Welcome.
    match bo
        .process_commit(GROUP, &added_cy.commit)
        .expect("bo processes the add commit")
    {
        Incoming::Commit(outcome) => {
            assert_eq!(outcome.sender.actor_id, "actor-ada");
            assert_eq!(outcome.added.len(), 1);
            assert_eq!(outcome.added[0].actor_id, "actor-cy");
            assert!(!outcome.removed_self);
        }
        other => panic!("expected a commit, got {other:?}"),
    }
    cy.join_from_welcome(&added_cy.welcome.clone().expect("welcome"))
        .expect("cy joins");

    // --- application messages, both directions ----------------------------
    let from_ada = ada.encrypt(GROUP, b"is this thing on").expect("encrypt");
    match bo.process_message(GROUP, &from_ada).expect("bo reads") {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-ada");
            assert_eq!(sender.device_id, "device-ada-phone");
            assert_eq!(plaintext, b"is this thing on");
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    let from_bo = bo.encrypt(GROUP, b"loud and clear").expect("encrypt");
    match ada.process_message(GROUP, &from_bo).expect("ada reads") {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-bo");
            assert_eq!(plaintext, b"loud and clear");
        }
        other => panic!("expected an application message, got {other:?}"),
    }
    // Cy is in the same epoch and reads it too.
    match cy.process_message(GROUP, &from_bo).expect("cy reads") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"loud and clear"),
        other => panic!("expected an application message, got {other:?}"),
    }

    // --- self-update: the epoch moves and everyone follows -----------------
    let rotated = ada.self_update(GROUP).expect("ada rotates her leaf");
    ada.merge_pending_commit(GROUP).expect("merge the rotation");
    for member in [&mut bo, &mut cy] {
        match member
            .process_commit(GROUP, &rotated.commit)
            .expect("the update commit applies")
        {
            Incoming::Commit(outcome) => {
                assert!(outcome.added.is_empty());
                assert!(outcome.removed.is_empty());
            }
            other => panic!("expected a commit, got {other:?}"),
        }
    }
    let epoch_after_update = ada.epoch(GROUP).expect("epoch");
    assert_eq!(bo.epoch(GROUP).expect("epoch"), epoch_after_update);
    assert_eq!(cy.epoch(GROUP).expect("epoch"), epoch_after_update);

    // Messages still flow after the rotation.
    let after_rotation = ada.encrypt(GROUP, b"still here").expect("encrypt");
    match bo
        .process_message(GROUP, &after_rotation)
        .expect("bo reads")
    {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"still here"),
        other => panic!("expected an application message, got {other:?}"),
    }

    // --- remove Bo --------------------------------------------------------
    let bo_leaf = ada
        .leaf_of_device(GROUP, "device-bo-phone")
        .expect("bo is in the roster");
    let removal = ada.remove_leaf(GROUP, bo_leaf).expect("remove bo");
    ada.merge_pending_commit(GROUP).expect("merge the removal");

    // Bo learns of his own removal and the group goes inactive for him.
    match bo
        .process_commit(GROUP, &removal.commit)
        .expect("bo processes")
    {
        Incoming::Commit(outcome) => {
            assert!(outcome.removed_self, "bo should see that he was removed");
            assert_eq!(outcome.removed, vec![bo_leaf]);
        }
        other => panic!("expected a commit, got {other:?}"),
    }
    assert!(!bo.is_active(GROUP).expect("group still known"));

    // Cy stays and follows the removal.
    match cy
        .process_commit(GROUP, &removal.commit)
        .expect("cy processes")
    {
        Incoming::Commit(outcome) => {
            assert!(!outcome.removed_self);
            assert_eq!(outcome.removed, vec![bo_leaf]);
        }
        other => panic!("expected a commit, got {other:?}"),
    }
    assert_eq!(ada.roster(GROUP).expect("roster").len(), 2);

    // --- the removed member cannot read what comes next -------------------
    let after_removal = ada.encrypt(GROUP, b"just us now").expect("encrypt");
    match cy
        .process_message(GROUP, &after_removal)
        .expect("cy still reads")
    {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"just us now"),
        other => panic!("expected an application message, got {other:?}"),
    }
    let refused = bo.process_message(GROUP, &after_removal);
    assert!(
        matches!(refused, Err(Error::NotAMember)),
        "a removed member must not decrypt the next message, got {refused:?}"
    );

    // ...and cannot send either.
    assert!(matches!(
        bo.encrypt(GROUP, b"let me back in"),
        Err(Error::NotAMember)
    ));
}

#[test]
fn an_exported_secret_is_shared_by_the_group_and_namespaced_by_label() {
    let server = issuer();
    let mut ada = client(&server, 4, "actor-ada", "device-ada-mac");
    let mut bo = client(&server, 5, "actor-bo", "device-bo-mac");

    ada.create_group(b"peachy-export").expect("create");
    let kp = bo.generate_key_package().expect("key package");
    let bundle = ada.add_member(b"peachy-export", &kp).expect("add");
    ada.merge_pending_commit(b"peachy-export").expect("merge");
    bo.join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");

    let mine = ada
        .export_secret(b"peachy-export", "peachy typing v1", b"", 32)
        .expect("export");
    let theirs = bo
        .export_secret(b"peachy-export", "peachy typing v1", b"", 32)
        .expect("export");
    assert_eq!(mine, theirs, "both members derive the same secret");
    assert_eq!(mine.len(), 32);

    let other_label = ada
        .export_secret(b"peachy-export", "peachy backups v1", b"", 32)
        .expect("export");
    assert_ne!(mine, other_label, "a different label is a different secret");

    let other_context = ada
        .export_secret(b"peachy-export", "peachy typing v1", b"thread-7", 32)
        .expect("export");
    assert_ne!(mine, other_context, "context separates too");

    assert!(ada
        .export_secret(b"peachy-export", "", b"", 32)
        .is_err_and(|err| matches!(err, Error::InvalidArgument(_))));
    assert!(ada
        .export_secret(b"peachy-export", "label", b"", 0)
        .is_err_and(|err| matches!(err, Error::InvalidArgument(_))));
}

#[test]
fn a_staged_commit_exports_the_secret_its_epoch_will_have() {
    // docs/delivery.md §SubmitCommit: SubmitCommit carries the NEXT epoch's
    // send-key verifier, so the committer must derive that epoch's exporter
    // secret while the commit is staged — and it must be the secret every
    // member derives once the commit is merged or processed.
    let server = issuer();
    let mut ada = client(&server, 6, "actor-ada", "device-ada-mac");
    let mut bo = client(&server, 7, "actor-bo", "device-bo-mac");
    let cy = client(&server, 8, "actor-cy", "device-cy-mac");
    const G: &[u8] = b"peachy-pending-export";
    const LABEL: &str = "peachy sealed-sender v1";

    ada.create_group(G).expect("create");
    assert!(
        ada.export_pending_secret(G, LABEL, G, 32).is_err(),
        "nothing is staged, so there is nothing to export from"
    );
    let kp = bo.generate_key_package().expect("key package");
    let bundle = ada.add_member(G, &kp).expect("add");
    let before = ada.export_secret(G, LABEL, G, 32).expect("current");
    let staged = ada.export_pending_secret(G, LABEL, G, 32).expect("staged");
    assert_ne!(before, staged, "the staged epoch is a new epoch");
    ada.merge_pending_commit(G).expect("merge");
    bo.join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");
    assert_eq!(ada.export_secret(G, LABEL, G, 32).expect("merged"), staged);
    assert_eq!(bo.export_secret(G, LABEL, G, 32).expect("joined"), staged);

    // And for a commit another member processes rather than joins by.
    let kp = cy.generate_key_package().expect("key package");
    let add_cy = ada.add_member(G, &kp).expect("add cy");
    let next = ada.export_pending_secret(G, LABEL, G, 32).expect("staged");
    ada.merge_pending_commit(G).expect("merge");
    bo.process_commit(G, &add_cy.commit).expect("bo processes");
    assert_eq!(bo.export_secret(G, LABEL, G, 32).expect("bo"), next);
}

#[test]
fn an_external_join_proposal_is_refused_by_policy() {
    use openmls::prelude::{
        tls_codec::Serialize as _, GroupEpoch, GroupId, JoinProposal, MlsMessageBodyIn,
        MlsMessageIn, ProtocolVersion,
    };
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::OpenMlsProvider;
    use tls_codec::Deserialize as _;

    let server = issuer();
    let mut ada = client(&server, 6, "actor-ada", "device-ada-ipad");
    let stranger = client(&server, 7, "actor-zed", "device-zed-phone");
    ada.create_group(b"peachy-external").expect("create");

    // A stranger with a perfectly valid Peachy credential proposes to add
    // themselves. This is the shape MLS calls an external add proposal: no
    // member consented to it, and Peachy's roster model says membership is
    // something a member did.
    let key_package_bytes = stranger.generate_key_package().expect("key package");
    let incoming = MlsMessageIn::tls_deserialize_exact(key_package_bytes.as_slice())
        .expect("a key package round-trips");
    let MlsMessageBodyIn::KeyPackage(key_package) = incoming.extract() else {
        panic!("a key package should decode as one");
    };
    let scratch = OpenMlsRustCrypto::default();
    let key_package = key_package
        .validate(scratch.crypto(), ProtocolVersion::Mls10)
        .expect("the stranger's key package is cryptographically fine");

    // The stranger signs the proposal with their own device key. Rebuilding
    // the signer here rather than reaching into the client is deliberate: the
    // point of the test is that a well-formed, correctly signed proposal from
    // a credentialled stranger is still refused.
    let seed = support::device_seed(7);
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&seed);
    let signer = openmls_basic_credential::SignatureKeyPair::from_raw(
        openmls_traits::types::SignatureScheme::ED25519,
        seed.to_vec(),
        public.to_vec(),
    );
    let proposal = JoinProposal::new::<<OpenMlsRustCrypto as OpenMlsProvider>::StorageProvider>(
        key_package,
        GroupId::from_slice(b"peachy-external"),
        GroupEpoch::from(0),
        &signer,
    )
    .expect("a join proposal can be built");

    let bytes = proposal
        .tls_serialize_detached()
        .expect("the proposal serializes");
    // Neither door takes a proposal: both refuse it before the engine reads it.
    for refused in [
        ada.process_message(b"peachy-external", &bytes),
        ada.process_commit(b"peachy-external", &bytes),
    ] {
        assert!(
            matches!(refused, Err(Error::WrongDoor(_))),
            "a door took an external join proposal, got {refused:?}"
        );
    }
    // And behind the doors, the engine refuses it as an external join.
    #[cfg(feature = "test-forgery")]
    {
        let refused = ada.forge_process_any(b"peachy-external", &bytes);
        assert!(
            matches!(
                refused,
                Err(Error::PolicyRefused(
                    peachy_mls_core::DenyReason::ExternalJoin
                ))
            ),
            "an external join must be refused as an external join, got {refused:?}"
        );
    }

    // And the refusal left no trace: the roster is still one leaf.
    assert_eq!(ada.roster(b"peachy-external").expect("roster").len(), 1);
    let _ = NOW;
}
