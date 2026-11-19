// SPDX-License-Identifier: MIT
//! A label owner's operations: initialization, learning of updates, and
//! monitoring, against an honest log and against one that adds or drops a
//! version behind the owner's back.

#![cfg(feature = "prover")]

mod verify_support;

use peachy_keytrans::verify::{ClientState, FailureKind, OwnerState, Verifier, VerifyError};
use verify_support::{owner, synced, ToyLog};

/// Learns every version the log holds past the owner's greatest.
fn learn(
    log: &mut ToyLog,
    verifier: &Verifier,
    state: &mut ClientState,
    me: &mut OwnerState,
) -> Vec<u64> {
    let mut request = me.update_request(state, Vec::new());
    let mut positions = Vec::new();
    for response in log.updates(&request) {
        let result = verifier
            .verify_update(state, me, &request, &response, log.now())
            .unwrap();
        assert!(!result.applied);
        positions.push(result.position);
        request = me.follow_on_request(state, &request, &response);
    }
    positions
}

/// Monitors until caught up, failing on the first error.
fn monitor(
    log: &mut ToyLog,
    verifier: &Verifier,
    state: &mut ClientState,
    me: &mut OwnerState,
) -> Result<bool, VerifyError> {
    for _ in 0..20 {
        let request = me.monitor_request(state);
        let response = log.owner_monitor(&request, 3);
        let result = verifier.verify_owner_monitor(state, me, &request, &response, log.now())?;
        if result.caught_up {
            return Ok(true);
        }
        if result.verified.is_empty() {
            return Ok(false);
        }
    }
    Ok(false)
}

fn start(state: &ClientState) -> u64 {
    state.distinguished.last().unwrap().position
}

#[test]
fn owner_of_a_new_label_follows_its_updates() {
    let mut log = ToyLog::new(20, 1);
    log.idle(12);
    let (verifier, mut state) = synced(&mut log);
    let s = start(&state);
    let mut me = owner(&mut log, &verifier, &mut state, b"me", s);
    assert_eq!(me.greatest(), None);
    assert!(learn(&mut log, &verifier, &mut state, &mut me).is_empty());

    // The log writes three versions, two of them in one entry.
    log.append(&[(b"me", b"v0")]);
    log.idle(2);
    log.append(&[(b"me", b"v1"), (b"other", b"x")]);
    log.idle(1);
    let p = log.append(&[(b"me", b"v2")]);
    log.idle(9);
    let learned = learn(&mut log, &verifier, &mut state, &mut me);
    assert_eq!(learned.len(), 3);
    assert_eq!(*learned.last().unwrap(), p);
    assert_eq!(me.greatest(), Some(2));
    assert!(monitor(&mut log, &verifier, &mut state, &mut me).unwrap());

    // Encodings round trip.
    let bytes = me.to_bytes().unwrap();
    assert_eq!(OwnerState::from_bytes(&bytes).unwrap(), me);
    let bytes = state.to_bytes().unwrap();
    assert_eq!(ClientState::from_bytes(&bytes).unwrap(), state);
}

#[test]
fn owner_of_an_existing_label_starts_at_a_distinguished_entry() {
    let mut log = ToyLog::new(21, 1);
    log.append(&[(b"me", b"v0")]);
    log.idle(3);
    log.append(&[(b"me", b"v1"), (b"me", b"v2")]);
    log.idle(14);
    let (verifier, mut state) = synced(&mut log);
    let s = start(&state);
    let mut me = owner(&mut log, &verifier, &mut state, b"me", s);
    assert_eq!(me.greatest(), Some(2));
    assert!(learn(&mut log, &verifier, &mut state, &mut me).is_empty());

    // The first update after initialization.
    log.append(&[(b"me", b"v3")]);
    log.idle(10);
    assert_eq!(learn(&mut log, &verifier, &mut state, &mut me).len(), 1);
    assert!(monitor(&mut log, &verifier, &mut state, &mut me).unwrap());
}

#[test]
fn a_version_the_owner_was_not_told_of_stops_monitoring() {
    let mut log = ToyLog::new(22, 1);
    log.append(&[(b"me", b"v0")]);
    log.idle(12);
    let (verifier, mut state) = synced(&mut log);
    let s = start(&state);
    let mut me = owner(&mut log, &verifier, &mut state, b"me", s);
    assert!(monitor(&mut log, &verifier, &mut state, &mut me).unwrap());

    // A version appears; the owner does not ask for updates. Monitoring
    // cannot get past the entry that holds it.
    log.append(&[(b"me", b"sneaky")]);
    log.idle(12);
    assert!(!monitor(&mut log, &verifier, &mut state, &mut me).unwrap());
    // Learning of it, the owner sees the value and can catch up.
    let learned = learn(&mut log, &verifier, &mut state, &mut me);
    assert_eq!(learned.len(), 1);
    assert!(monitor(&mut log, &verifier, &mut state, &mut me).unwrap());
}

#[test]
fn a_version_dropped_from_the_log_fails_monitoring() {
    let mut log = ToyLog::new(23, 1);
    log.append(&[(b"me", b"v0")]);
    log.idle(4);
    log.append(&[(b"me", b"v1")]);
    log.idle(12);
    let (verifier, mut state) = synced(&mut log);
    let s = start(&state);
    let mut me = owner(&mut log, &verifier, &mut state, b"me", s);
    assert!(monitor(&mut log, &verifier, &mut state, &mut me).unwrap());
    let before = me.clone();

    log.drop_version(b"me", 1);
    log.idle(12);
    let err = monitor(&mut log, &verifier, &mut state, &mut me).unwrap_err();
    assert!(matches!(err, VerifyError::VersionMismatch(_)), "{err:?}");
    assert_eq!(err.kind(), FailureKind::BadProof);
    assert_eq!(me, before, "a failed response leaves the owner state alone");
}

#[test]
fn update_responses_are_checked_against_the_owner() {
    let mut log = ToyLog::new(24, 1);
    log.idle(12);
    let (verifier, mut state) = synced(&mut log);
    let s = start(&state);
    let mut me = owner(&mut log, &verifier, &mut state, b"me", s);
    log.append(&[(b"me", b"v0")]);
    log.idle(3);
    let request = me.update_request(&state, Vec::new());
    let responses = log.updates(&request);

    // Wrong opening: the commitment does not match the tree.
    let mut bad = responses[0].clone();
    bad.info[0].opening[9] ^= 1;
    assert!(verifier
        .verify_update(
            &mut state.clone(),
            &mut me.clone(),
            &request,
            &bad,
            log.now()
        )
        .is_err());

    // Wrong value.
    let mut bad = responses[0].clone();
    bad.values[0].value = b"evil".to_vec();
    assert!(verifier
        .verify_update(
            &mut state.clone(),
            &mut me.clone(),
            &request,
            &bad,
            log.now()
        )
        .is_err());

    // An insertion claimed at or before the owner's start.
    let mut bad = responses[0].clone();
    bad.position = s;
    assert_eq!(
        verifier
            .verify_update(
                &mut state.clone(),
                &mut me.clone(),
                &request,
                &bad,
                log.now()
            )
            .unwrap_err(),
        VerifyError::Proof("an update not after the previous insertion")
    );

    // A request that does not fit the owner.
    let mut other = request.clone();
    other.greatest_version = Some(5);
    assert_eq!(
        verifier
            .verify_update(&mut state, &mut me, &other, &responses[0], log.now())
            .unwrap_err()
            .kind(),
        FailureKind::Usage
    );

    verifier
        .verify_update(&mut state, &mut me, &request, &responses[0], log.now())
        .unwrap();
    assert_eq!(me.greatest(), Some(0));
}
