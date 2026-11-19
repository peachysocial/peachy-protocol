// SPDX-License-Identifier: MIT
//! Every response the prover gives, over seeded random histories, is
//! accepted by a reference verifier built only on the verifier-side math
//! (`prefix_proof::evaluate`, `log_tree::verify_batch`, `ladder::drive`).

#![cfg(feature = "prover")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod prover_support;

use peachy_keytrans::implicit::ancestors;
use peachy_keytrans::prover::{Recent, Storage};
use peachy_keytrans::wire::{
    ContactMonitorRequest, Credential, CredentialBody, DistinguishedRequest, MonitorMapEntry,
    OwnerInitRequest, OwnerMonitorRequest, SearchRequest, UpdateRequest,
};
use prover_support::algorithms::{
    verify_contact, verify_credential, verify_credential_update, verify_distinguished,
    verify_owner_init, verify_owner_monitor, verify_search, verify_updates,
};
use prover_support::{label, Rng, World, WINDOW};

const LABELS: u64 = 4;

/// `last` values to ask with: none, the current size (a `same` head) and
/// one smaller size.
fn lasts(n: u64, rng: &mut Rng) -> Vec<Option<u64>> {
    let mut v = vec![None, Some(n)];
    if n > 1 {
        v.push(Some(1 + rng.below(n - 1)));
    }
    v
}

/// Up to three versions to look at: the first, a middle one and the last.
fn sample(g: Option<u32>) -> Vec<u32> {
    let Some(g) = g else { return vec![] };
    let mut v = vec![0, g / 2, g];
    v.dedup();
    v
}

/// Up to three of `xs`: the first, a middle one and the last.
fn pick(xs: &[u64]) -> Vec<u64> {
    let mut v: Vec<u64> = [xs.first(), xs.get(xs.len() / 2), xs.last()]
        .into_iter()
        .flatten()
        .copied()
        .collect();
    v.dedup();
    v
}

/// The monitoring map of every version that is the first one created at
/// its entry, from `after` on.
fn map_from(w: &World, l: &[u8], after: u64) -> Vec<MonitorMapEntry> {
    let mut out: Vec<MonitorMapEntry> = Vec::new();
    for r in w.prover.store().label_versions(l).unwrap() {
        if r.position < after || out.last().is_some_and(|e| e.position == r.position) {
            continue;
        }
        out.push(MonitorMapEntry {
            position: r.position,
            version: r.version,
        });
    }
    out
}

struct Counts {
    responses: usize,
}

fn check_all(w: &World, rng: &mut Rng, creds: &mut Vec<(Credential, u64)>, counts: &mut Counts) {
    let n = w.n();
    let d = w.prover.distinguished_entries().unwrap();
    for last in lasts(n, rng) {
        for recent in [
            Recent::Within(3 * WINDOW),
            Recent::Rightmost(2),
            Recent::Rightmost(1000),
        ] {
            for stop in [None, d.get(d.len() / 2).copied()] {
                let req = DistinguishedRequest { last, stop };
                let resp = w.prover.distinguished(&req, recent).unwrap();
                let seen = verify_distinguished(w, &req, &resp, recent).unwrap();
                assert!(seen.iter().all(|x| d.contains(x)));
                counts.responses += 1;
            }
        }

        for i in 0..LABELS {
            let l = label(i);
            let g = w.greatest_at(&l, n - 1);

            let req = SearchRequest {
                last,
                label: l.clone(),
                version: None,
            };
            match w.prover.search(&req).unwrap() {
                Some(resp) => {
                    assert_eq!(resp.version, g);
                    verify_search(w, &req, &resp).unwrap();
                    counts.responses += 1;
                }
                None => assert_eq!(g, None),
            }
            for v in sample(g) {
                let req = SearchRequest {
                    last,
                    label: l.clone(),
                    version: Some(v),
                };
                let resp = w.prover.search(&req).unwrap().unwrap();
                assert_eq!(resp.version, None);
                verify_search(w, &req, &resp).unwrap();
                counts.responses += 1;
            }
            let beyond = SearchRequest {
                last,
                label: l.clone(),
                version: Some(g.map_or(0, |g| g + 1)),
            };
            assert!(w.prover.search(&beyond).unwrap().is_none());

            // Contact monitoring: one version at a time, at its entry and
            // at the nearest ancestor to its right; then the whole map.
            for v in sample(g) {
                let p = w.first_position(&l, v);
                let mut positions = vec![p];
                if let Some(a) = ancestors(p, n).unwrap().into_iter().find(|&a| a > p) {
                    positions.push(a);
                }
                for position in positions {
                    let req = ContactMonitorRequest {
                        last,
                        label: l.clone(),
                        entries: vec![MonitorMapEntry {
                            position,
                            version: v,
                        }],
                    };
                    let resp = w.prover.contact_monitor(&req).unwrap();
                    verify_contact(w, &req, &resp).unwrap();
                    counts.responses += 1;
                }
            }
            let req = ContactMonitorRequest {
                last,
                label: l.clone(),
                entries: map_from(w, &l, 0),
            };
            let resp = w.prover.contact_monitor(&req).unwrap();
            verify_contact(w, &req, &resp).unwrap();
            counts.responses += 1;

            for &start in &pick(&d) {
                let req = OwnerInitRequest {
                    last,
                    label: l.clone(),
                    start,
                };
                let resp = w.prover.owner_init(&req).unwrap();
                verify_owner_init(w, &req, &resp).unwrap();
                counts.responses += 1;

                for max_ladders in [usize::MAX, 1] {
                    let req = OwnerMonitorRequest {
                        last,
                        label: l.clone(),
                        entries: map_from(w, &l, start + 1),
                        start,
                        greatest_version: g,
                    };
                    let resp = w.prover.owner_monitor(&req, max_ladders).unwrap();
                    verify_owner_monitor(w, &req, &resp).unwrap();
                    counts.responses += 1;
                }
            }

            let mut knowns: Vec<Option<u32>> = vec![None];
            knowns.extend(sample(g).into_iter().map(Some));
            for known in knowns {
                for max in [255, 2] {
                    let req = UpdateRequest {
                        last,
                        label: l.clone(),
                        greatest_version: known,
                        values: vec![],
                    };
                    let resps = w.prover.update(&req, max).unwrap();
                    assert!(resps.len() <= max);
                    if max == 255 {
                        let expected = match (known, g) {
                            (Some(k), Some(g)) if k == g => 0,
                            (_, None) => 0,
                            _ => 1,
                        };
                        assert!(resps.len() >= expected);
                    }
                    verify_updates(w, &req, &resps).unwrap();
                    counts.responses += resps.len();
                }
            }
        }
    }

    // Credentials, kept to be updated at later sizes.
    for &position in &pick(&d) {
        for i in 0..LABELS {
            let Some(cred) = w.prover.credential(&label(i), position).unwrap() else {
                assert_eq!(w.greatest_at(&label(i), n - 1), None);
                continue;
            };
            let terminal = verify_credential(w, &cred).unwrap();
            counts.responses += 1;
            if let Some(t) = terminal {
                creds.push((cred, t));
            }
        }
    }
    creds.retain(
        |(cred, terminal)| match w.prover.credential_update(cred).unwrap() {
            Some(upd) => {
                verify_credential_update(w, cred, *terminal, &upd).unwrap();
                counts.responses += 1;
                false
            }
            None => true,
        },
    );
}

fn run(seed: u64, entries: u64, checkpoints: &[u64]) -> usize {
    let mut w = World::new();
    let mut rng = Rng::new(seed);
    let mut creds = Vec::new();
    let mut counts = Counts { responses: 0 };
    for i in 0..entries {
        let count = match rng.below(10) {
            0..=2 => 0,
            3..=7 => 1,
            _ => 1 + rng.below(3),
        };
        let updates: Vec<u64> = (0..count).map(|_| rng.below(LABELS)).collect();
        let gap = match rng.below(6) {
            0 => 2 * WINDOW,
            1 => WINDOW,
            _ => WINDOW / 10 + rng.below(WINDOW / 3),
        };
        w.append(gap, &updates);
        if i % 5 == 2 {
            let size = w.n();
            let back = rng.below(size.min(4));
            w.audit((i % 2) as usize, size - back);
        }
        if checkpoints.contains(&(i + 1)) {
            check_all(&w, &mut rng, &mut creds, &mut counts);
        }
    }
    for (cred, _) in &creds {
        let CredentialBody::Provisional { .. } = cred.body else {
            panic!("only provisional credentials wait for an update");
        };
    }
    counts.responses
}

#[test]
fn small_logs() {
    let mut total = 0;
    for seed in 1..=4 {
        total += run(seed, 9, &[1, 2, 3, 5, 9]);
    }
    assert!(total > 100);
}

#[test]
fn a_longer_log() {
    let total = run(77, 40, &[13, 27, 40]);
    assert!(total > 100);
}

#[test]
fn a_log_of_heartbeats_and_bursts() {
    // Long quiet stretches (every entry distinguished) then bursts inside
    // one window (few distinguished), so walks reach every depth.
    let mut w = World::new();
    let mut rng = Rng::new(5);
    let mut creds = Vec::new();
    let mut counts = Counts { responses: 0 };
    for round in 0..3u64 {
        for _ in 0..4 {
            w.append(3 * WINDOW, &[]);
        }
        for k in 0..6u64 {
            w.append(7, &[(round + k) % LABELS]);
        }
        check_all(&w, &mut rng, &mut creds, &mut counts);
    }
    assert!(counts.responses > 100);
}
