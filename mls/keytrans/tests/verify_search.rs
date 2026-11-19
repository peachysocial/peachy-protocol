// SPDX-License-Identifier: MIT
//! Search, contact monitoring and the checks every response shares: tree
//! heads, auditor heads, the clock window and consistency with the
//! retained view.

#![cfg(feature = "prover")]

mod verify_support;

use peachy_keytrans::verify::{
    AuditorKey, ClientState, ContactMonitor, FailureKind, OwnerState, Verifier, VerifyError,
};
use peachy_keytrans::wire::FullTreeHead;
use verify_support::{synced, ToyLog, STEP};

fn populated(seed: u8) -> ToyLog {
    let mut log = ToyLog::new(seed, 2);
    log.append(&[(b"alice", b"a0")]);
    log.idle(5);
    log.append(&[(b"bob", b"b0"), (b"alice", b"a1")]);
    log.idle(9);
    log.append(&[(b"alice", b"a2")]);
    log.idle(3);
    log
}

#[test]
fn greatest_and_fixed_searches_verify() {
    let mut log = populated(1);
    let verifier = Verifier::new(log.deployment.clone()).unwrap();
    let mut state = ClientState::new();

    let (req, resp) = log.search(None, b"alice", None);
    let found = verifier
        .verify_search(&mut state, &req, &resp, log.now())
        .unwrap();
    assert_eq!(found.version, 2);
    assert_eq!(found.value, b"a2");
    assert_eq!(state.last(), Some(log.len()));

    // The same tree head again.
    let (req, resp) = log.search(state.last(), b"alice", Some(0));
    assert_eq!(resp.full_tree_head, FullTreeHead::Same);
    let found = verifier
        .verify_search(&mut state, &req, &resp, log.now())
        .unwrap();
    assert_eq!((found.version, found.value.as_slice()), (0, &b"a0"[..]));

    // A newer one, consistent with the first.
    log.append(&[(b"alice", b"a3")]);
    log.idle(2);
    let (req, resp) = log.search(state.last(), b"alice", None);
    let found = verifier
        .verify_search(&mut state, &req, &resp, log.now())
        .unwrap();
    assert_eq!(found.version, 3);

    let (req, resp) = log.search(state.last(), b"bob", Some(0));
    verifier
        .verify_search(&mut state, &req, &resp, log.now())
        .unwrap();
}

#[test]
fn absent_versions_and_labels_are_verified_not_found() {
    let mut log = populated(2);
    let (verifier, mut state) = synced(&mut log);
    let before = state.clone();
    let (req, resp) = log.search(state.last(), b"alice", Some(7));
    let err = verifier
        .verify_search(&mut state, &req, &resp, log.now())
        .unwrap_err();
    assert_eq!(err, VerifyError::VersionNotFound);
    assert_eq!(err.kind(), FailureKind::NotFound);
    assert_eq!(state, before, "a failed verification changes nothing");

    let (req, resp) = log.search(state.last(), b"carol", Some(0));
    assert_eq!(
        verifier
            .verify_search(&mut state, &req, &resp, log.now())
            .unwrap_err(),
        VerifyError::VersionNotFound
    );
}

#[test]
fn a_hidden_newer_version_is_caught() {
    let mut log = populated(3);
    let verifier = Verifier::new(log.deployment.clone()).unwrap();
    let mut state = ClientState::new();
    let (req, mut resp) = log.search(None, b"alice", None);
    // Claim version 1 is the greatest while version 2 exists: the proof
    // for version 2 does not read as one for version 1.
    let v1 = log.labels[&b"alice"[..]][1].clone();
    resp.version = Some(1);
    resp.opening = v1.opening;
    resp.value.value = v1.value;
    resp.binary_ladder = log.ladder_steps(
        b"alice",
        &peachy_keytrans::verify::base_ladder(Some(1)),
        |v| v < 1,
    );
    let err = verifier
        .verify_search(&mut state, &req, &resp, log.now())
        .unwrap_err();
    assert_eq!(err.kind(), FailureKind::BadProof, "{err:?}");
    assert_eq!(state, ClientState::new());
}

#[test]
fn tampered_responses_fail() {
    let mut log = populated(4);
    let verifier = Verifier::new(log.deployment.clone()).unwrap();
    let (req, resp) = log.search(None, b"alice", None);

    let mut bad = resp.clone();
    bad.search.timestamps[0] += 1;
    // A changed timestamp either reshapes the walk (expiry and the
    // distinguished entries depend on it) or, with nothing retained, moves
    // the root so the log's signature no longer covers it.
    let err = verifier
        .verify_search(&mut ClientState::new(), &req, &bad, log.now())
        .unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::BadTreeHeadSignature { slot: 0 } | VerifyError::Proof(_)
        ),
        "{err:?}"
    );

    let mut bad = resp.clone();
    bad.search.timestamps.swap(0, 1);
    assert!(verifier
        .verify_search(&mut ClientState::new(), &req, &bad, log.now())
        .is_err());

    let mut bad = resp.clone();
    bad.binary_ladder[0].proof[5] ^= 1;
    assert_eq!(
        verifier
            .verify_search(&mut ClientState::new(), &req, &bad, log.now())
            .unwrap_err()
            .kind(),
        FailureKind::BadProof
    );

    let mut bad = resp.clone();
    bad.value.value = b"evil".to_vec();
    assert!(verifier
        .verify_search(&mut ClientState::new(), &req, &bad, log.now())
        .is_err());

    let mut bad = resp.clone();
    bad.search.prefix_proofs.pop();
    assert!(verifier
        .verify_search(&mut ClientState::new(), &req, &bad, log.now())
        .is_err());

    let mut bad = resp;
    bad.search.inclusion.elements[0][0] ^= 1;
    assert!(verifier
        .verify_search(&mut ClientState::new(), &req, &bad, log.now())
        .is_err());
}

#[test]
fn tree_head_and_auditor_checks() {
    let mut log = populated(5);
    let verifier = Verifier::new(log.deployment.clone()).unwrap();
    let (req, resp) = log.search(None, b"alice", None);

    // A log signature broken for the second auditor's configuration.
    let mut bad = resp.clone();
    if let FullTreeHead::Updated { tree_head, .. } = &mut bad.full_tree_head {
        tree_head.signatures[1].signature[0] ^= 1;
    }
    assert_eq!(
        verifier
            .verify_search(&mut ClientState::new(), &req, &bad, log.now())
            .unwrap_err(),
        VerifyError::BadTreeHeadSignature { slot: 1 }
    );

    // An auditor's head missing.
    let mut bad = resp.clone();
    if let FullTreeHead::Updated {
        auditor_tree_heads, ..
    } = &mut bad.full_tree_head
    {
        auditor_tree_heads.remove(0);
    }
    assert_eq!(
        verifier
            .verify_search(&mut ClientState::new(), &req, &bad, log.now())
            .unwrap_err(),
        VerifyError::MissingAuditor { slot: 0 }
    );

    // An auditor's head signature broken.
    let mut bad = resp;
    if let FullTreeHead::Updated {
        auditor_tree_heads, ..
    } = &mut bad.full_tree_head
    {
        auditor_tree_heads[1].auditor_tree_head.signature[3] ^= 1;
    }
    assert_eq!(
        verifier
            .verify_search(&mut ClientState::new(), &req, &bad, log.now())
            .unwrap_err(),
        VerifyError::BadAuditorSignature { slot: 1 }
    );

    // A stale auditor: its head is 25 entries (25 s) behind, past the
    // 20 s lag.
    log.idle(30);
    log.auditor_lag[0] = Some(25);
    let (req, resp) = log.search(None, b"alice", None);
    assert_eq!(
        verifier
            .verify_search(&mut ClientState::new(), &req, &resp, log.now())
            .unwrap_err(),
        VerifyError::AuditorLag { slot: 0 }
    );
    // Within the lag it passes.
    log.auditor_lag[0] = Some(10);
    let (req, resp) = log.search(None, b"alice", None);
    verifier
        .verify_search(&mut ClientState::new(), &req, &resp, log.now())
        .unwrap();
}

#[test]
fn a_live_auditor_key_is_asked_for_then_accepted() {
    let mut log = populated(6);
    let mut deployment = log.deployment.clone();
    deployment.auditors[1].key = AuditorKey::Live;
    let verifier = Verifier::new(deployment.clone()).unwrap();
    let mut state = ClientState::new();
    let (req, resp) = log.search(None, b"alice", None);
    let err = verifier
        .verify_search(&mut state, &req, &resp, log.now())
        .unwrap_err();
    let key = log.auditor_keys[1].public_key().to_bytes();
    assert_eq!(err, VerifyError::UnknownAuditorKeys(vec![key]));
    assert_eq!(err.kind(), FailureKind::NeedAuditorKey);
    state.accept_auditor_key(&deployment, 1, key, 0).unwrap();
    verifier
        .verify_search(&mut state, &req, &resp, log.now())
        .unwrap();
    // A pinned slot takes no run-time key.
    assert!(state.accept_auditor_key(&deployment, 0, key, 0).is_err());
}

#[test]
fn the_clock_window_is_enforced() {
    let mut log = populated(7);
    let verifier = Verifier::new(log.deployment.clone()).unwrap();
    let (req, resp) = log.search(None, b"alice", None);
    let now = log.now();
    assert_eq!(
        verifier
            .verify_search(&mut ClientState::new(), &req, &resp, now + 101 * STEP)
            .unwrap_err(),
        VerifyError::TooFarBehind { by: 101 * STEP }
    );
    assert_eq!(
        verifier
            .verify_search(&mut ClientState::new(), &req, &resp, now - 11 * STEP)
            .unwrap_err(),
        VerifyError::TooFarAhead { by: 11 * STEP }
    );
    verifier
        .verify_search(&mut ClientState::new(), &req, &resp, now + 99 * STEP)
        .unwrap();

    // A `same` head is held to the window too.
    let mut state = ClientState::new();
    verifier
        .verify_search(&mut state, &req, &resp, now)
        .unwrap();
    let (req, resp) = log.search(state.last(), b"alice", None);
    assert_eq!(
        verifier
            .verify_search(&mut state, &req, &resp, now + 101 * STEP)
            .unwrap_err()
            .kind(),
        FailureKind::LogFault
    );
}

#[test]
fn a_fork_is_caught_as_inconsistent() {
    let mut a = populated(8);
    let mut b = a.clone();
    let verifier = Verifier::new(a.deployment.clone()).unwrap();
    let mut state = ClientState::new();
    a.append(&[(b"alice", b"honest")]);
    b.append(&[(b"alice", b"forged")]);
    let (req, resp) = a.search(None, b"alice", None);
    verifier
        .verify_search(&mut state, &req, &resp, a.now())
        .unwrap();
    // The client then talks to the fork, which shares the prefix up to
    // the divergence but not the entry the client verified.
    b.idle(4);
    let (req, resp) = b.search(state.last(), b"alice", None);
    let err = verifier
        .verify_search(&mut state, &req, &resp, b.now())
        .unwrap_err();
    assert_eq!(err.kind(), FailureKind::LogFault, "{err:?}");
}

#[test]
fn requests_must_fit_the_state() {
    let mut log = populated(9);
    let (verifier, mut state) = synced(&mut log);
    log.idle(1);
    let (mut req, resp) = log.search(state.last(), b"alice", None);
    req.last = None;
    assert_eq!(
        verifier
            .verify_search(&mut state, &req, &resp, log.now())
            .unwrap_err()
            .kind(),
        FailureKind::Usage
    );
    // `same` to a client that advertised nothing.
    let (req, mut resp) = log.search(None, b"alice", None);
    resp.full_tree_head = FullTreeHead::Same;
    assert_eq!(
        verifier
            .verify_search(&mut ClientState::new(), &req, &resp, log.now())
            .unwrap_err(),
        VerifyError::UnadvertisedSame
    );
    // An `updated` head that is not newer than the one advertised.
    let (mut req, resp) = log.search(None, b"alice", None);
    req.last = state.last();
    let mut stale = resp;
    if let FullTreeHead::Updated { tree_head, .. } = &mut stale.full_tree_head {
        tree_head.tree_size = state.last().unwrap();
    }
    assert_eq!(
        verifier
            .verify_search(&mut state, &req, &stale, log.now())
            .unwrap_err(),
        VerifyError::HeadNotNewer
    );
}

#[test]
fn contact_monitoring_follows_a_version_up_to_a_distinguished_entry() {
    let mut log = ToyLog::new(10, 1);
    log.idle(9);
    log.append(&[(b"dana", b"d0")]);
    let verifier = Verifier::new(log.deployment.clone()).unwrap();
    let mut state = ClientState::new();
    let (req, resp) = log.search(None, b"dana", None);
    let found = verifier
        .verify_search(&mut state, &req, &resp, log.now())
        .unwrap();
    let mut monitor: ContactMonitor = found.monitor;
    assert!(!monitor.is_done());
    let mut rounds = 0;
    while !monitor.is_done() {
        log.idle(3);
        let req = monitor.request(&state);
        let resp = log.contact_monitor(&req);
        verifier
            .verify_contact_monitor(&mut state, &mut monitor, &req, &resp, log.now())
            .unwrap();
        rounds += 1;
        assert!(rounds < 20, "monitoring never finished");
    }
    // Round trips.
    let bytes = monitor.to_bytes().unwrap();
    assert_eq!(ContactMonitor::from_bytes(&bytes).unwrap(), monitor);
    let bytes = state.to_bytes().unwrap();
    assert_eq!(ClientState::from_bytes(&bytes).unwrap(), state);
    assert!(ClientState::from_bytes(&bytes[1..]).is_err());
    assert!(OwnerState::from_bytes(&[]).is_err());
}

#[test]
fn contact_monitoring_catches_a_version_dropped_from_the_log() {
    let mut log = ToyLog::new(11, 1);
    // The version at entry 8, whose parent in a tree of 10 is entry 9.
    log.idle(8);
    log.append(&[(b"erin", b"e0")]);
    let verifier = Verifier::new(log.deployment.clone()).unwrap();
    let mut state = ClientState::new();
    let (req, resp) = log.search(None, b"erin", None);
    let found = verifier
        .verify_search(&mut state, &req, &resp, log.now())
        .unwrap();
    let mut monitor = found.monitor;
    assert_eq!(monitor.entries[0].position, 8);
    // Entry 9 leaves the version out of its prefix tree: the monitoring
    // ladder there cannot show it.
    log.drop_version(b"erin", 0);
    log.idle(1);
    let req = monitor.request(&state);
    let resp = log.contact_monitor(&req);
    assert!(!resp.monitor.prefix_proofs.is_empty());
    let before = (state.clone(), monitor.clone());
    let err = verifier
        .verify_contact_monitor(&mut state, &mut monitor, &req, &resp, log.now())
        .unwrap_err();
    assert!(matches!(err, VerifyError::VersionMismatch(_)), "{err:?}");
    assert_eq!((state, monitor), before, "a failure changes nothing");
}
