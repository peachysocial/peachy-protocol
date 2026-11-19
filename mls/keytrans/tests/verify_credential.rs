// SPDX-License-Identifier: MIT
//! Distinguished walks and the transparency proofs anchored at them.

#![cfg(feature = "prover")]

mod verify_support;

use peachy_keytrans::verify::{ClientState, FailureKind, PendingCredential, VerifyError};
use peachy_keytrans::wire::CredentialBody;
use verify_support::{synced, ToyLog};

#[test]
fn distinguished_walks_keep_each_entrys_tree() {
    let mut log = ToyLog::new(30, 2);
    log.idle(40);
    let (verifier, mut state) = synced(&mut log);
    assert!(!state.distinguished.is_empty());
    assert!(state.distinguished.len() <= 8);
    for d in &state.distinguished {
        let n = d.position + 1;
        assert_eq!(d.full_subtrees, log.tree.full_subtree_values(n).unwrap());
        assert_eq!(d.entry, log.entries[d.position as usize]);
    }
    // A later walk stops at the newest held entry, and agrees with it.
    log.idle(9);
    let request = state.distinguished_request();
    assert!(request.stop.is_some());
    let response = log.distinguished(&request);
    let found = verifier
        .verify_distinguished(&mut state, &request, &response, log.now())
        .unwrap();
    assert!(!found.is_empty());
    for d in &state.distinguished {
        assert_eq!(
            d.full_subtrees,
            log.tree.full_subtree_values(d.position + 1).unwrap()
        );
    }
    let bytes = state.to_bytes().unwrap();
    assert_eq!(ClientState::from_bytes(&bytes).unwrap(), state);
}

#[test]
fn standard_credentials_verify_against_a_held_entry() {
    let mut log = ToyLog::new(31, 1);
    log.append(&[(b"cred", b"c0")]);
    log.append(&[(b"cred", b"c1")]);
    log.idle(20);
    let (verifier, state) = synced(&mut log);
    let d = state.distinguished.last().unwrap().position;
    let credential = log.credential(b"cred", d);
    assert!(matches!(credential.body, CredentialBody::Standard { .. }));
    let result = verifier.verify_credential(&state, &credential).unwrap();
    assert_eq!((result.version, result.value.as_slice()), (1, &b"c1"[..]));
    assert!(result.pending.is_none());

    // Tampered: a peer's bad proof is a bad proof, not a log fault.
    let mut bad = credential.clone();
    if let CredentialBody::Standard { distinguished } = &mut bad.body {
        distinguished.elements[0][0] ^= 1;
    }
    let err = verifier.verify_credential(&state, &bad).unwrap_err();
    assert_eq!(err.kind(), FailureKind::BadProof, "{err:?}");

    let mut bad = credential.clone();
    bad.value.value = b"evil".to_vec();
    assert_eq!(
        verifier.verify_credential(&state, &bad).unwrap_err().kind(),
        FailureKind::BadProof
    );

    // An anchor the client does not hold.
    let mut bad = credential;
    bad.position = d + 1;
    let err = verifier.verify_credential(&state, &bad).unwrap_err();
    assert_eq!(err, VerifyError::UnknownDistinguished { position: d + 1 });
    assert_eq!(err.kind(), FailureKind::NeedDistinguished);
}

#[test]
fn provisional_credentials_verify_then_complete() {
    let mut log = ToyLog::new(32, 1);
    log.append(&[(b"cred", b"c0")]);
    log.idle(20);
    let (verifier, mut state) = synced(&mut log);
    let d = state.distinguished.last().unwrap().position;

    // A new version after the anchor: only a provisional proof can show it.
    let terminal = log.append(&[(b"cred", b"c1")]);
    let credential = log.credential(b"cred", d);
    assert!(matches!(
        credential.body,
        CredentialBody::Provisional { .. }
    ));
    let before = state.clone();
    let result = verifier.verify_credential(&state, &credential).unwrap();
    assert_eq!(state, before, "a transparency proof changes no state");
    assert_eq!(result.version, 1);
    let pending: PendingCredential = result.pending.unwrap();
    assert_eq!(pending.terminal, terminal);
    let bytes = pending.to_bytes().unwrap();
    assert_eq!(PendingCredential::from_bytes(&bytes).unwrap(), pending);

    // A broken log signature in the proof is the peer's problem.
    let mut bad = credential.clone();
    if let CredentialBody::Provisional { tree_head, .. } = &mut bad.body {
        tree_head.signatures[0].signature[1] ^= 1;
    }
    assert_eq!(
        verifier.verify_credential(&state, &bad).unwrap_err().kind(),
        FailureKind::BadProof
    );

    // Later, a distinguished entry covers the version.
    log.idle(12);
    let request = state.distinguished_request();
    let response = log.distinguished(&request);
    verifier
        .verify_distinguished(&mut state, &request, &response, log.now())
        .unwrap();
    let q = state
        .distinguished
        .iter()
        .map(|e| e.position)
        .find(|&p| p > terminal)
        .unwrap();
    let update = log.credential_update(b"cred", 1, terminal, pending.tree_size, q);
    verifier
        .verify_credential_update(&state, &pending, &update)
        .unwrap();

    // The wrong anchor for the update.
    let mut wrong = update.clone();
    wrong.position = d;
    assert!(verifier
        .verify_credential_update(&state, &pending, &wrong)
        .is_err());

    // A tampered update.
    let mut bad = update;
    if let Some(p) = bad.monitor.prefix_proofs.first_mut() {
        p.elements[0][0] ^= 1;
    } else {
        bad.monitor.inclusion.elements[0][0] ^= 1;
    }
    assert_eq!(
        verifier
            .verify_credential_update(&state, &pending, &bad)
            .unwrap_err()
            .kind(),
        FailureKind::BadProof
    );
}
