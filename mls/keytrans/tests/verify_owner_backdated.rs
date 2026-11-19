// SPDX-License-Identifier: MIT
//! An owner refuses an update claimed at an entry its monitoring has already
//! covered.
//!
//! Owner monitoring checks the entries up to `start` once and never again,
//! and when an update's insertion entry is distinguished, verifying the
//! update leaves the proof that the new version is there to that
//! monitoring. A log that claimed a new version at a distinguished entry
//! between the owner's last insertion and `start` would have it accepted
//! with no proof it exists, and could then serve the same value to
//! contacts as a real later version without the owner's monitoring
//! noticing. `verify_update` refuses any insertion at or before `start`.

#![cfg(feature = "prover")]

mod verify_support;

use std::collections::BTreeSet;

use peachy_keytrans::suite::Opening;
use peachy_keytrans::verify::{
    base_ladder, ClientState, FailureKind, OwnerState, ProofRecorder, UpdateClaims, Verifier,
    VerifyError, Walk,
};
use peachy_keytrans::wire::{FullTreeHead, LabelValue, UpdateInfo, UpdateRequest, UpdateResponse};

use verify_support::{owner, synced, ToyLog};

/// The distinguished entries of the log as it stands, ascending.
fn distinguished_positions(log: &mut ToyLog) -> Vec<u64> {
    let n = log.len();
    let window = log.deployment.reasonable_monitoring_window;
    let mut src = log.source(b"");
    let mut rec = ProofRecorder::new(&mut src, None).unwrap();
    let mut walk = Walk::new(&mut rec, n, window, None);
    (1..n)
        .filter(|&x| walk.is_distinguished(x).unwrap())
        .collect()
}

/// A forged `UpdateResponse` saying `new_versions` of `label` went in at
/// the distinguished entry `position`, with `value` and `opening` and an
/// unchanged tree (`FullTreeHead::Same`). Nothing was added to the log.
///
/// It follows the honest prover in `ToyLog::updates`, but drives the update
/// walk with made-up claims. At a distinguished entry with one new version
/// the walk never looks that version up, so no leaf has to exist.
#[allow(clippy::too_many_arguments)]
fn forged_update(
    log: &mut ToyLog,
    label: &[u8],
    previous: Option<u32>,
    position: u64,
    new_versions: &[u32],
    value: &[u8],
    opening: Opening,
    last: Option<u64>,
) -> UpdateResponse {
    let n = log.len();
    let window = log.deployment.reasonable_monitoring_window;
    let g_new = *new_versions.last().unwrap();

    let mut wanted: BTreeSet<u32> = base_ladder(Some(g_new)).into_iter().collect();
    if new_versions.len() > 1 {
        wanted.extend(new_versions);
    }
    match previous {
        Some(g) => {
            for v in base_ladder(Some(g)) {
                wanted.remove(&v);
            }
        }
        None => {
            wanted.remove(&0);
        }
    }
    let wanted: Vec<u32> = wanted.into_iter().collect();
    // VRF proofs for the wanted versions, commitments only for the versions
    // that really exist (at or below `previous`), as an honest log shows.
    let binary_ladder = log.ladder_steps(label, &wanted, |v| previous.is_some_and(|g| v <= g));
    let (full_tree_head, extra) = log.full_head(last, n);

    let claims = UpdateClaims {
        position,
        previous_greatest: previous,
        new_versions,
    };
    let update = {
        let mut src = log.source(label);
        let mut rec = ProofRecorder::new(&mut src, last).unwrap();
        {
            let mut walk = Walk::new(&mut rec, n, window, None);
            walk.update_view(last).unwrap();
            walk.update(&claims).unwrap();
        }
        rec.finish(n, last, &extra).unwrap()
    };

    UpdateResponse {
        full_tree_head,
        position,
        values: new_versions
            .iter()
            .map(|_| LabelValue {
                value: value.to_vec(),
            })
            .collect(),
        info: new_versions
            .iter()
            .map(|_| UpdateInfo { opening })
            .collect(),
        binary_ladder,
        update,
    }
}

/// The opening `ToyLog::append` gives `label`'s `version` appended at
/// `position`, so a later real insertion commits to exactly what the forged
/// update claimed.
fn append_opening(label: &[u8], version: u32, position: u64) -> Opening {
    let mut opening = [0u8; 16];
    opening[0] = version as u8;
    opening[1] = position as u8;
    opening[2] = label.len() as u8;
    opening
}

const FORGED_VALUE: &[u8] = b"a key the owner never published";

/// An owner whose monitoring has run well past its only insertion, and a
/// forged update for version 1 at a distinguished entry in between.
struct Setup {
    log: ToyLog,
    verifier: Verifier,
    state: ClientState,
    me: OwnerState,
    request: UpdateRequest,
    forged: UpdateResponse,
    /// Where the next real append lands.
    next_position: u64,
}

fn setup() -> Setup {
    // A 32-entry log: version 0 of "me" at position 3, nothing else.
    let mut log = ToyLog::new(77, 1);
    log.idle(3);
    assert_eq!(log.append(&[(b"me", b"v0")]), 3);
    log.idle(28);
    assert_eq!(log.len(), 32);

    // The owner starts at the first distinguished entry holding version 0,
    // so its one recorded insertion sits far to the left.
    let dist = distinguished_positions(&mut log);
    let first = *dist.iter().find(|&&p| p >= 3).unwrap();
    let (verifier, mut state) = synced(&mut log);
    let mut me = owner(&mut log, &verifier, &mut state, b"me", first);
    assert_eq!(me.greatest(), Some(0));
    assert_eq!(me.greatest_position(), first);

    // Monitoring moves `start` right; the insertion stays where it was.
    for _ in 0..20 {
        let request = me.monitor_request(&state);
        let response = log.owner_monitor(&request, 3);
        let result = verifier
            .verify_owner_monitor(&mut state, &mut me, &request, &response, log.now())
            .unwrap();
        if result.caught_up {
            break;
        }
    }
    assert_eq!(me.greatest_position(), first);

    // A distinguished entry after the insertion but already monitored.
    let claimed = *dist
        .iter()
        .find(|&&p| p > me.greatest_position() && p < me.start)
        .expect("a distinguished entry between the insertion and start");

    let next_position = log.len();
    let request = me.update_request(&state, Vec::new());
    assert_eq!(request.greatest_version, Some(0));
    let forged = forged_update(
        &mut log,
        b"me",
        Some(0),
        claimed,
        &[1],
        FORGED_VALUE,
        append_opening(b"me", 1, next_position),
        request.last,
    );
    assert!(matches!(forged.full_tree_head, FullTreeHead::Same));

    Setup {
        log,
        verifier,
        state,
        me,
        request,
        forged,
        next_position,
    }
}

/// Refuses the forged update, leaves the owner's state as it was, and asserts
/// the refusal is a proof failure.
fn refuse(s: &mut Setup) {
    let before = (s.state.clone(), s.me.clone());
    let err = s
        .verifier
        .verify_update(&mut s.state, &mut s.me, &s.request, &s.forged, s.log.now())
        .expect_err("an update at an already-monitored entry is refused");
    assert!(matches!(err, VerifyError::Proof(_)), "{err:?}");
    assert_eq!(err.kind(), FailureKind::BadProof);
    assert_eq!((s.state.clone(), s.me.clone()), before);
}

/// Owner monitoring, a round at a time until it reports caught up: whether
/// it did within 20 rounds. An honest log stops a round at an entry holding
/// a version the owner has not learned yet, so the owner stays behind until
/// an update tells it. Every round must verify.
fn monitor(s: &mut Setup) -> bool {
    for _ in 0..20 {
        let request = s.me.monitor_request(&s.state);
        let response = s.log.owner_monitor(&request, 3);
        let result = s
            .verifier
            .verify_owner_monitor(&mut s.state, &mut s.me, &request, &response, s.log.now())
            .unwrap();
        if result.caught_up {
            return true;
        }
    }
    false
}

#[test]
fn an_update_at_an_already_monitored_entry_is_refused() {
    let mut s = setup();
    refuse(&mut s);
    assert_eq!(s.me.greatest(), Some(0));
    // Nothing changed in the log, so monitoring still passes.
    assert!(monitor(&mut s));
}

/// The log then really appends a version 1, either the forged value (which,
/// before the fix, the owner had recorded already and monitored straight
/// past) or a different one. Either way the owner is not told it is caught
/// up while the log holds a version it never accepted, and the update that
/// brings it in hands the owner the value to check against what it knows.
#[test]
fn a_version_appended_after_the_refusal_reaches_the_owner() {
    for value in [FORGED_VALUE, b"a different value".as_slice()] {
        let mut s = setup();
        refuse(&mut s);
        assert_eq!(s.log.append(&[(b"me", value)]), s.next_position);
        s.log.idle(16);

        // A contact is served the value, with valid proofs.
        let (contact, mut contact_state) = synced(&mut s.log);
        let (req, resp) = s.log.search(contact_state.last(), b"me", None);
        let found = contact
            .verify_search(&mut contact_state, &req, &resp, s.log.now())
            .unwrap();
        assert_eq!((found.version, found.value.as_slice()), (1, value));

        assert!(
            !monitor(&mut s),
            "monitoring reported caught up past a version the owner never accepted"
        );

        let request = s.me.update_request(&s.state, Vec::new());
        let responses = s.log.updates(&request);
        assert_eq!(responses.len(), 1);
        let result = s
            .verifier
            .verify_update(
                &mut s.state,
                &mut s.me,
                &request,
                &responses[0],
                s.log.now(),
            )
            .unwrap();
        assert_eq!(result.position, s.next_position);
        assert_eq!(result.created, vec![(1u32, value.to_vec())]);
        assert!(monitor(&mut s));
    }
}

/// Control: the same owner takes a genuine update, which lands past
/// `start`, and is handed the value to check against what it knows.
#[test]
fn a_genuine_update_after_start_is_accepted() {
    let mut s = setup();
    let start = s.me.start;
    let position = s.log.append(&[(b"me", b"v1")]);
    assert!(position > start);
    s.log.idle(2);

    let request = s.me.update_request(&s.state, Vec::new());
    let responses = s.log.updates(&request);
    assert_eq!(responses.len(), 1);
    let result = s
        .verifier
        .verify_update(
            &mut s.state,
            &mut s.me,
            &request,
            &responses[0],
            s.log.now(),
        )
        .unwrap();
    assert_eq!(result.position, position);
    assert!(!result.applied);
    assert_eq!(result.created, vec![(1u32, b"v1".to_vec())]);
    assert_eq!(s.me.greatest(), Some(1));
    assert!(monitor(&mut s));
}
