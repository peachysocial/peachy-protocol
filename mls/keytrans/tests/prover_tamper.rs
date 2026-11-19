// SPDX-License-Identifier: MIT
//! Tampered responses are refused: every single change to a proof's
//! timestamps, prefix proofs, prefix roots or inclusion proof, a proof
//! removed or added, a ladder step's VRF proof, or the value or opening a
//! commitment covers, makes the reference verifier fail.

#![cfg(feature = "prover")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod prover_support;

use peachy_keytrans::prover::Recent;
use peachy_keytrans::wire::{
    BinaryLadderStep, CombinedTreeProof, ContactMonitorRequest, DistinguishedRequest,
    MonitorMapEntry, OwnerInitRequest, OwnerMonitorRequest, PrefixSearchOutcome, SearchRequest,
    UpdateRequest,
};
use peachy_keytrans::Result;
use prover_support::algorithms::{
    verify_contact, verify_credential, verify_credential_update, verify_distinguished,
    verify_owner_init, verify_owner_monitor, verify_search, verify_updates,
};
use prover_support::{label, World, WINDOW};

/// Every single-field change to `p` this test makes, named.
fn tampers(p: &CombinedTreeProof) -> Vec<(String, CombinedTreeProof)> {
    let mut out = Vec::new();
    let mut add = |name: String, f: &dyn Fn(&mut CombinedTreeProof)| {
        let mut q = p.clone();
        f(&mut q);
        if q != *p {
            out.push((name, q));
        }
    };
    for i in 0..p.timestamps.len() {
        add(format!("timestamp {i} later"), &|q| q.timestamps[i] += 1);
        add(format!("timestamp {i} removed"), &|q| {
            q.timestamps.remove(i);
        });
    }
    add("a timestamp added".into(), &|q| {
        q.timestamps.push(u64::MAX / 2)
    });
    for i in 0..p.prefix_proofs.len() {
        for j in 0..p.prefix_proofs[i].elements.len() {
            add(format!("prefix proof {i} element {j}"), &|q| {
                q.prefix_proofs[i].elements[j][0] ^= 1;
            });
        }
        add(format!("prefix proof {i} element added"), &|q| {
            q.prefix_proofs[i].elements.push([9; 32]);
        });
        for j in 0..p.prefix_proofs[i].results.len() {
            add(format!("prefix proof {i} result {j} depth"), &|q| {
                let r = &mut q.prefix_proofs[i].results[j];
                r.depth = r.depth.wrapping_add(1);
            });
            add(format!("prefix proof {i} result {j} outcome"), &|q| {
                let r = &mut q.prefix_proofs[i].results[j];
                r.outcome = match r.outcome {
                    PrefixSearchOutcome::Inclusion => PrefixSearchOutcome::NonInclusionParent,
                    _ => PrefixSearchOutcome::Inclusion,
                };
            });
            add(format!("prefix proof {i} result {j} removed"), &|q| {
                q.prefix_proofs[i].results.remove(j);
            });
        }
        add(format!("prefix proof {i} removed"), &|q| {
            q.prefix_proofs.remove(i);
        });
        add(format!("prefix proof {i} repeated"), &|q| {
            let again = q.prefix_proofs[i].clone();
            q.prefix_proofs.insert(i, again);
        });
    }
    for i in 0..p.prefix_roots.len() {
        add(format!("prefix root {i}"), &|q| q.prefix_roots[i][31] ^= 1);
        add(format!("prefix root {i} removed"), &|q| {
            q.prefix_roots.remove(i);
        });
    }
    add("a prefix root added".into(), &|q| {
        q.prefix_roots.push([5; 32])
    });
    for i in 0..p.inclusion.elements.len() {
        add(format!("inclusion element {i}"), &|q| {
            q.inclusion.elements[i][3] ^= 0x80
        });
        add(format!("inclusion element {i} removed"), &|q| {
            q.inclusion.elements.remove(i);
        });
    }
    add("an inclusion element added".into(), &|q| {
        q.inclusion.elements.push([1; 32])
    });
    out
}

/// Ladder steps with one VRF proof flipped, one at a time.
fn ladder_tampers(steps: &[BinaryLadderStep]) -> Vec<(String, Vec<BinaryLadderStep>)> {
    let mut out = Vec::new();
    for i in 0..steps.len() {
        let mut s = steps.to_vec();
        s[i].proof[40] ^= 1;
        out.push((format!("ladder step {i} proof"), s));
    }
    if let Some(i) = steps.iter().position(|s| s.commitment.is_some()) {
        let mut s = steps.to_vec();
        s[i].commitment = None;
        out.push((format!("ladder step {i} commitment dropped"), s));
    }
    if !steps.is_empty() {
        let mut s = steps.to_vec();
        s.pop();
        out.push(("ladder step removed".into(), s));
    }
    out
}

fn refused(what: &str, name: &str, r: Result<impl Sized>) -> usize {
    assert!(r.is_err(), "{what}: tampering with {name} went unnoticed");
    1
}

fn world() -> World {
    let mut w = World::new();
    // Quiet stretches and bursts, with auditor heads, so proofs carry
    // timestamps, ladders, prefix roots and extra sizes.
    for round in 0..3u64 {
        for _ in 0..3 {
            w.append(2 * WINDOW, &[]);
        }
        for k in 0..5u64 {
            w.append(11, &[(round + k) % 3]);
        }
        let n = w.n();
        w.audit((round % 2) as usize, n - 1);
    }
    w
}

#[test]
fn tampered_responses_are_refused() {
    let w = world();
    let n = w.n();
    let l = label(1);
    let d = w.prover.distinguished_entries().unwrap();
    let start = d[d.len() / 2];
    let mut checked = 0usize;

    for last in [None, Some(n), Some(n / 2)] {
        // Search, greatest and fixed.
        for version in [None, Some(0), Some(2)] {
            let req = SearchRequest {
                last,
                label: l.clone(),
                version,
            };
            let resp = w.prover.search(&req).unwrap().unwrap();
            verify_search(&w, &req, &resp).unwrap();
            for (name, p) in tampers(&resp.search) {
                let mut t = resp.clone();
                t.search = p;
                checked += refused("search", &name, verify_search(&w, &req, &t));
            }
            for (name, s) in ladder_tampers(&resp.binary_ladder) {
                let mut t = resp.clone();
                t.binary_ladder = s;
                checked += refused("search", &name, verify_search(&w, &req, &t));
            }
            let mut t = resp.clone();
            t.value.value.push(0);
            checked += refused("search", "the value", verify_search(&w, &req, &t));
            let mut t = resp.clone();
            t.opening[0] ^= 1;
            checked += refused("search", "the opening", verify_search(&w, &req, &t));
        }

        // Contact monitoring.
        let first = w.first_position(&l, 0);
        let req = ContactMonitorRequest {
            last,
            label: l.clone(),
            entries: vec![MonitorMapEntry {
                position: first,
                version: 0,
            }],
        };
        let resp = w.prover.contact_monitor(&req).unwrap();
        verify_contact(&w, &req, &resp).unwrap();
        for (name, p) in tampers(&resp.monitor) {
            let mut t = resp.clone();
            t.monitor = p;
            checked += refused("contact", &name, verify_contact(&w, &req, &t));
        }

        // Owner initialization and monitoring.
        let req = OwnerInitRequest {
            last,
            label: l.clone(),
            start,
        };
        let resp = w.prover.owner_init(&req).unwrap();
        verify_owner_init(&w, &req, &resp).unwrap();
        for (name, p) in tampers(&resp.init) {
            let mut t = resp.clone();
            t.init = p;
            checked += refused("owner init", &name, verify_owner_init(&w, &req, &t));
        }
        for (name, s) in ladder_tampers(&resp.binary_ladder) {
            let mut t = resp.clone();
            t.binary_ladder = s;
            checked += refused("owner init", &name, verify_owner_init(&w, &req, &t));
        }
        if !resp.greatest_versions.is_empty() {
            let mut t = resp.clone();
            t.greatest_versions[0] += 1;
            checked += refused(
                "owner init",
                "a greatest version",
                verify_owner_init(&w, &req, &t),
            );
        }

        let req = OwnerMonitorRequest {
            last,
            label: l.clone(),
            entries: vec![],
            start,
            greatest_version: w.greatest_at(&l, n - 1),
        };
        let resp = w.prover.owner_monitor(&req, usize::MAX).unwrap();
        verify_owner_monitor(&w, &req, &resp).unwrap();
        // Dropping the walk's last ladder can make a valid shorter
        // response (when its entry needs no prefix root of its own): the
        // log may stop at any step 4, and the owner stops where the
        // response ends and asks again (§8.3). So that change is not
        // asserted either way.
        let truncation = format!(
            "prefix proof {} removed",
            resp.monitor.prefix_proofs.len() - 1
        );
        for (name, p) in tampers(&resp.monitor) {
            if name == truncation {
                continue;
            }
            let mut t = resp.clone();
            t.monitor = p;
            checked += refused("owner monitor", &name, verify_owner_monitor(&w, &req, &t));
        }

        // Update, from a version whose successor was created at an entry
        // that is not distinguished, so the response carries the search
        // ladder there (§9.1 step 4) and binds every new value. At a
        // distinguished entry (step 3) versions on the new greatest
        // version's ladder are checked later, by owner monitoring.
        let known = (0..w.greatest_at(&l, n - 1).unwrap())
            .find(|&v| !d.contains(&w.first_position(&l, v + 1)))
            .expect("an update at an entry that is not distinguished");
        let req = UpdateRequest {
            last,
            label: l.clone(),
            greatest_version: Some(known),
            values: vec![],
        };
        let resps = w.prover.update(&req, 1).unwrap();
        verify_updates(&w, &req, &resps).unwrap();
        let resp = &resps[0];
        for (name, p) in tampers(&resp.update) {
            let mut t = resp.clone();
            t.update = p;
            checked += refused("update", &name, verify_updates(&w, &req, &[t]));
        }
        for (name, s) in ladder_tampers(&resp.binary_ladder) {
            let mut t = resp.clone();
            t.binary_ladder = s;
            checked += refused("update", &name, verify_updates(&w, &req, &[t]));
        }
        let mut t = resp.clone();
        t.values[0].value.push(1);
        checked += refused("update", "a value", verify_updates(&w, &req, &[t]));
        let mut t = resp.clone();
        t.info[0].opening[5] ^= 1;
        checked += refused("update", "an opening", verify_updates(&w, &req, &[t]));

        // Distinguished walk.
        let req = DistinguishedRequest { last, stop: None };
        let recent = Recent::Rightmost(1000);
        let resp = w.prover.distinguished(&req, recent).unwrap();
        verify_distinguished(&w, &req, &resp, recent).unwrap();
        for (name, p) in tampers(&resp.distinguished) {
            let mut t = resp.clone();
            t.distinguished = p;
            checked += refused(
                "distinguished",
                &name,
                verify_distinguished(&w, &req, &t, recent),
            );
        }
    }
    assert!(checked > 300, "only {checked} tampers checked");
}

#[test]
fn tampered_credentials_are_refused() {
    let mut w = world();
    let l = label(0);
    let d = w.prover.distinguished_entries().unwrap();
    let mut provisional = None;
    let mut checked = 0usize;
    for &position in &d {
        let cred = w.prover.credential(&l, position).unwrap().unwrap();
        verify_credential(&w, &cred).unwrap();
        for (name, s) in ladder_tampers(&cred.binary_ladder) {
            let mut t = cred.clone();
            t.binary_ladder = s;
            checked += refused("credential", &name, verify_credential(&w, &t));
        }
        let mut t = cred.clone();
        t.value.value.push(2);
        checked += refused("credential", "the value", verify_credential(&w, &t));
        match &cred.body {
            peachy_keytrans::wire::CredentialBody::Standard { distinguished } => {
                let wrapped = CombinedTreeProof {
                    timestamps: vec![],
                    prefix_proofs: vec![distinguished.clone()],
                    prefix_roots: vec![],
                    inclusion: peachy_keytrans::wire::InclusionProof { elements: vec![] },
                };
                for (name, p) in tampers(&wrapped) {
                    if p.prefix_proofs.len() != 1 || p.prefix_proofs == wrapped.prefix_proofs {
                        continue;
                    }
                    let mut t = cred.clone();
                    t.body = peachy_keytrans::wire::CredentialBody::Standard {
                        distinguished: p.prefix_proofs[0].clone(),
                    };
                    checked += refused("standard credential", &name, verify_credential(&w, &t));
                }
            }
            peachy_keytrans::wire::CredentialBody::Provisional { tree_head, search } => {
                for (name, p) in tampers(search) {
                    let mut t = cred.clone();
                    t.body = peachy_keytrans::wire::CredentialBody::Provisional {
                        tree_head: tree_head.clone(),
                        search: p,
                    };
                    checked += refused("provisional credential", &name, verify_credential(&w, &t));
                }
                provisional.get_or_insert(cred.clone());
            }
        }
    }

    // A provisional credential: make one, then its update.
    let cred = match provisional {
        Some(c) => c,
        None => {
            let anchor = w.prover.rightmost_distinguished().unwrap().unwrap();
            w.append(3, &[0]);
            w.prover.credential(&l, anchor).unwrap().unwrap()
        }
    };
    let terminal = verify_credential(&w, &cred).unwrap().expect("provisional");
    let mut upd = w.prover.credential_update(&cred).unwrap();
    while upd.is_none() {
        w.append(2 * WINDOW, &[]);
        upd = w.prover.credential_update(&cred).unwrap();
    }
    let upd = upd.unwrap();
    verify_credential_update(&w, &cred, terminal, &upd).unwrap();
    for (name, p) in tampers(&upd.monitor) {
        let mut t = upd.clone();
        t.monitor = p;
        checked += refused(
            "credential update",
            &name,
            verify_credential_update(&w, &cred, terminal, &t),
        );
    }
    let mut t = upd.clone();
    t.position += 1;
    checked += refused(
        "credential update",
        "the position",
        verify_credential_update(&w, &cred, terminal, &t),
    );
    assert!(checked > 20, "only {checked} tampers checked");
}
