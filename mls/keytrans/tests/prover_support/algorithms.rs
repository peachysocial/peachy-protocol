// SPDX-License-Identifier: MIT
//! The algorithms, as a verifier runs them over the reference consumer.

use std::collections::{BTreeMap, BTreeSet};

use peachy_keytrans::head::verify_tree_head;
use peachy_keytrans::implicit::{ancestors, frontier, left, right, root, spans_window};
use peachy_keytrans::ladder::{drive, LadderKind};
use peachy_keytrans::prefix_proof::{evaluate, PrefixSearch};
use peachy_keytrans::prover::{Recent, Storage};
use peachy_keytrans::wire::{
    ContactMonitorRequest, ContactMonitorResponse, Credential, CredentialBody, CredentialUpdate,
    DistinguishedRequest, DistinguishedResponse, MonitorMapEntry, OwnerInitRequest,
    OwnerInitResponse, OwnerMonitorRequest, OwnerMonitorResponse, PrefixSearchOutcome,
    SearchRequest, SearchResponse, UpdateRequest, UpdateResponse, UpdateValue,
};
use peachy_keytrans::{Error, Result};

use super::{base, check_roots, Consumer, Keys, Known, World, WINDOW};

fn bad(why: &'static str) -> Error {
    Error::ProofMismatch(why)
}

/// The rightmost distinguished entry, from the consumer's timestamps.
fn rightmost_distinguished(c: &mut Consumer<'_>) -> Result<Option<u64>> {
    let n = c.n;
    let rt = c.timestamp(n - 1)?;
    let mut x = root(n)?;
    let mut lt = 0;
    let mut found = None;
    loop {
        if !spans_window(lt, rt, WINDOW) {
            return Ok(found);
        }
        found = Some(x);
        let Some(next) = right(x, n) else {
            return Ok(found);
        };
        lt = c.timestamp(x)?;
        x = next;
    }
}

/// §6.3; returns the terminal entry.
pub fn greatest_search(c: &mut Consumer<'_>, keys: &Keys, g: u32) -> Result<u64> {
    let n = c.n;
    let start = match rightmost_distinguished(c)? {
        Some(x) => x,
        None => root(n)?,
    };
    let mut known = Known::default();
    let mut terminal = None;
    let f = frontier(n);
    for &x in f.iter().skip_while(|&&x| x != start) {
        let end = c.ladder(x, LadderKind::Search { target: g }, keys, Some(&mut known))?;
        if end.above_target {
            return Err(bad("a version above the claimed greatest"));
        }
        if x == n - 1 && end.below_target_missing {
            return Err(bad("the claimed greatest is missing at the right"));
        }
        if terminal.is_none() && !end.below_target_missing {
            terminal = Some(x);
        }
    }
    terminal.ok_or(bad("no terminal entry"))
}

pub fn verify_search(w: &World, req: &SearchRequest, resp: &SearchResponse) -> Result<()> {
    let n = w.n();
    let extra = w.check_head(&resp.full_tree_head, req.last, n);
    let target = match req.version {
        Some(t) => t,
        None => resp.version.ok_or(bad("no version"))?,
    };
    let mut keys = Keys::default();
    keys.absorb(
        &w.vrf_public,
        &req.label,
        &base(target),
        &resp.binary_ladder,
    )?;
    if resp
        .binary_ladder
        .iter()
        .zip(base(target))
        .any(|(s, v)| v == target && s.commitment.is_some())
    {
        return Err(bad("commitment given for the target"));
    }
    keys.target(&req.label, target, &resp.opening, &resp.value);
    let mut c = Consumer::new(&resp.search, n, req.last, w.retained(req.last));
    c.update_view()?;
    if req.version.is_none() {
        greatest_search(&mut c, &keys, target)?;
    } else {
        let mut known = Known::both();
        let mut x = root(n)?;
        let mut greater: Option<u64> = None;
        let mut done = false;
        loop {
            let end = c.ladder(x, LadderKind::Search { target }, &keys, Some(&mut known))?;
            let next = if end.below_target_missing {
                right(x, n)
            } else if end.above_target {
                greater = Some(greater.map_or(x, |g: u64| g.min(x)));
                left(x)
            } else {
                done = true;
                break;
            };
            match next {
                Some(y) => x = y,
                None => break,
            }
        }
        if !done {
            let at = greater.ok_or(bad("version does not exist"))?;
            let out = c.prefix(
                at,
                &[PrefixSearch {
                    vrf_output: keys.outputs[&target],
                    commitment: keys.commitments.get(&target).copied(),
                }],
            )?;
            if out != [PrefixSearchOutcome::Inclusion] {
                return Err(bad("target not included at the greater entry"));
            }
        }
    }
    let roots = c.finish(&extra)?;
    check_roots(w, n, &extra, roots)
}

/// §8.2 over `entries`; `owner_start` inside owner monitoring.
pub fn contact(
    c: &mut Consumer<'_>,
    keys: &Keys,
    entries: &[MonitorMapEntry],
    owner_start: Option<u64>,
) -> Result<()> {
    let n = c.n;
    let mut laddered: BTreeMap<u64, u32> = BTreeMap::new();
    for e in entries.iter().rev() {
        let p = e.position;
        if c.is_distinguished(p)? {
            continue;
        }
        let mut list = Vec::new();
        let mut ends = false;
        for a in ancestors(p, n)? {
            if a < p {
                continue;
            }
            list.push(a);
            if c.is_distinguished(a)? {
                ends = true;
                break;
            }
        }
        if ends && owner_start.is_some_and(|s| p >= s) {
            list.pop();
        }
        for y in list {
            if let Some(&t) = laddered.get(&y) {
                if t > e.version {
                    break;
                }
                return Err(bad("monitoring map inconsistent"));
            }
            let end = c.ladder(y, LadderKind::Monitor { target: e.version }, keys, None)?;
            if end.below_target_missing {
                return Err(bad("monitored version missing"));
            }
            laddered.insert(y, e.version);
        }
    }
    Ok(())
}

/// The keys of every version up to `upto`, as an owner or monitor holds
/// them from earlier responses, and the VRF outputs of `upto`'s base
/// ladder, which those responses also carried. A search ladder whose
/// target is at most `upto` looks up nothing else.
pub fn known_keys(w: &World, label: &[u8], upto: Option<u32>) -> Keys {
    let mut k = Keys::default();
    let records = w.prover.store().label_versions(label).unwrap();
    for r in records
        .iter()
        .filter(|r| upto.is_some_and(|u| r.version <= u))
    {
        k.outputs.insert(r.version, r.vrf_output);
        k.commitments.insert(r.version, r.commitment);
    }
    for v in base(upto.unwrap_or(0)) {
        k.outputs.entry(v).or_insert_with(|| w.output(label, v));
    }
    k
}

pub fn verify_contact(
    w: &World,
    req: &ContactMonitorRequest,
    resp: &ContactMonitorResponse,
) -> Result<()> {
    let n = w.n();
    let extra = w.check_head(&resp.full_tree_head, req.last, n);
    let max = req.entries.iter().map(|e| e.version).max();
    let keys = known_keys(w, &req.label, max);
    let mut c = Consumer::new(&resp.monitor, n, req.last, w.retained(req.last));
    c.update_view()?;
    contact(&mut c, &keys, &req.entries, None)?;
    let roots = c.finish(&extra)?;
    check_roots(w, n, &extra, roots)
}

pub fn verify_owner_init(
    w: &World,
    req: &OwnerInitRequest,
    resp: &OwnerInitResponse,
) -> Result<()> {
    let n = w.n();
    let extra = w.check_head(&resp.full_tree_head, req.last, n);
    let start = req.start;
    let up = ancestors(start, n)?;
    let list: Vec<u64> = std::iter::once(start)
        .chain(up.iter().copied().filter(|&a| a < start))
        .collect();
    let g = &resp.greatest_versions;
    if g.len() > list.len() || g.windows(2).any(|p| p[0] < p[1]) {
        return Err(bad("greatest versions malformed"));
    }
    let mut vs: BTreeSet<u32> = BTreeSet::from([0]);
    for &v in g {
        vs.extend(base(v));
    }
    let vs: Vec<u32> = vs.into_iter().collect();
    let mut keys = Keys::default();
    keys.absorb(&w.vrf_public, &req.label, &vs, &resp.binary_ladder)?;
    for &v in g {
        if !keys.commitments.contains_key(&v) {
            return Err(bad("no commitment for a greatest version"));
        }
    }
    let mut c = Consumer::new(&resp.init, n, req.last, w.retained(req.last));
    c.update_view()?;
    for &y in up.iter().rev() {
        c.timestamp(y)?;
    }
    c.timestamp(start)?;
    if !c.is_distinguished(start)? {
        return Err(bad("start not distinguished"));
    }
    for (i, &x) in list.iter().enumerate() {
        let claimed = g.get(i).copied();
        let end = c.ladder(
            x,
            LadderKind::Search {
                target: claimed.unwrap_or(0),
            },
            &keys,
            None,
        )?;
        match claimed {
            Some(_) if end.above_target || end.below_target_missing => {
                return Err(bad("ladder disagrees with the claimed version"))
            }
            None if !end.below_target_missing => {
                return Err(bad("label claimed absent is present"))
            }
            _ => {}
        }
    }
    let roots = c.finish(&extra)?;
    check_roots(w, n, &extra, roots)
}

pub fn verify_owner_monitor(
    w: &World,
    req: &OwnerMonitorRequest,
    resp: &OwnerMonitorResponse,
) -> Result<()> {
    let n = w.n();
    let extra = w.check_head(&resp.full_tree_head, req.last, n);
    let max = req
        .entries
        .iter()
        .map(|e| e.version)
        .chain(req.greatest_version)
        .max();
    let keys = known_keys(w, &req.label, max);
    let mut c = Consumer::new(&resp.monitor, n, req.last, w.retained(req.last));
    c.update_view()?;
    contact(&mut c, &keys, &req.entries, Some(req.start))?;
    let rt = c.timestamp(n - 1)?;
    owner_walk(w, &mut c, &keys, req, root(n)?, 0, rt)?;
    let roots = c.finish(&extra)?;
    check_roots(w, n, &extra, roots)
}

/// Returns false once the response is consumed.
fn owner_walk(
    w: &World,
    c: &mut Consumer<'_>,
    keys: &Keys,
    req: &OwnerMonitorRequest,
    x: u64,
    lt: u64,
    rt: u64,
) -> Result<bool> {
    let n = c.n;
    if !spans_window(lt, rt, WINDOW) {
        return Ok(true);
    }
    if x <= req.start {
        if let Some(r) = right(x, n) {
            let t = c.timestamp(x)?;
            return owner_walk(w, c, keys, req, r, t, rt);
        }
        return Ok(true);
    }
    if let Some(l) = left(x) {
        let t = c.timestamp(x)?;
        if !owner_walk(w, c, keys, req, l, lt, t)? {
            return Ok(false);
        }
    }
    if !c.proofs_left() {
        return Ok(false);
    }
    // The owner's local state: what it expects here.
    let expected = w.greatest_at(&req.label, x);
    let end = c.ladder(
        x,
        LadderKind::Search {
            target: expected.unwrap_or(0),
        },
        keys,
        None,
    )?;
    match expected {
        Some(_) if end.above_target || end.below_target_missing => return Err(bad("owner ladder")),
        None if !end.below_target_missing => return Err(bad("owner ladder on an absent label")),
        _ => {}
    }
    if let Some(r) = right(x, n) {
        let t = c.timestamp(x)?;
        return owner_walk(w, c, keys, req, r, t, rt);
    }
    Ok(true)
}

/// Verifies a series of update responses (§13.5), processed in order.
pub fn verify_updates(w: &World, req: &UpdateRequest, resps: &[UpdateResponse]) -> Result<()> {
    let n = w.n();
    let mut known = req.greatest_version;
    let mut last = req.last;
    for resp in resps {
        let extra = w.check_head(&resp.full_tree_head, last, n);
        let first = known.map_or(0, |g| g + 1);
        if resp.values.is_empty() || resp.values.len() != resp.info.len() {
            return Err(bad("values and info"));
        }
        let newest = first + resp.values.len() as u32 - 1;
        let p = resp.position;
        let mut set: BTreeSet<u32> = base(newest).into_iter().collect();
        if newest > first {
            set.extend(first..=newest);
        }
        let old: Vec<u32> = known.map_or(vec![0], base);
        let set: Vec<u32> = set.into_iter().filter(|v| !old.contains(v)).collect();
        let mut keys = known_keys(w, &req.label, known);
        for &v in &old {
            keys.outputs.insert(v, w.output(&req.label, v));
        }
        keys.absorb(&w.vrf_public, &req.label, &set, &resp.binary_ladder)?;
        if resp
            .binary_ladder
            .iter()
            .zip(&set)
            .any(|(s, v)| s.commitment.is_some() != known.is_some_and(|g| *v <= g))
        {
            return Err(bad("commitments in the update ladder"));
        }
        for (i, (value, info)) in resp.values.iter().zip(&resp.info).enumerate() {
            let v = first + i as u32;
            keys.target(
                &req.label,
                v,
                &info.opening,
                &UpdateValue {
                    value: value.value.clone(),
                },
            );
        }

        let mut c = Consumer::new(&resp.update, n, last, w.retained(last));
        c.update_view()?;
        if p > 0 {
            c.is_distinguished(p - 1)?;
        }
        let here = c.is_distinguished(p)?;
        let prev = frontier(p);
        let mut from = prev.len();
        for (i, &y) in prev.iter().enumerate() {
            if !c.is_distinguished(y)? {
                from = i;
                break;
            }
        }
        let target = known.unwrap_or(0);
        let mut k = Known::default();
        for &y in prev.iter().skip(from) {
            let end = c.ladder(y, LadderKind::Search { target }, &keys, Some(&mut k))?;
            // Nothing above `G` before `P`; with no `G`, no version at all.
            if end.above_target || (known.is_none() && !end.below_target_missing) {
                return Err(bad("previous tree ladder"));
            }
        }
        let ladder_vs = base(newest);
        if !here {
            let end = c.ladder(
                p,
                LadderKind::Search { target: newest },
                &keys,
                Some(&mut k),
            )?;
            if end.above_target || end.below_target_missing {
                return Err(bad("new greatest version ladder"));
            }
        }
        let outside: Vec<u32> = (first..=newest)
            .filter(|v| !ladder_vs.contains(v))
            .collect();
        if !outside.is_empty() {
            let searches: Vec<PrefixSearch> = outside
                .iter()
                .map(|v| PrefixSearch {
                    vrf_output: keys.outputs[v],
                    commitment: keys.commitments.get(v).copied(),
                })
                .collect();
            let res = c.prefix(p, &searches)?;
            if res.iter().any(|r| *r != PrefixSearchOutcome::Inclusion) {
                return Err(bad("new version not included"));
            }
        }
        let roots = c.finish(&extra)?;
        check_roots(w, n, &extra, roots)?;
        if w.first_position(&req.label, first) != p {
            return Err(bad("position"));
        }
        known = Some(newest);
        last = Some(n);
    }
    Ok(())
}

/// §10.1; returns the distinguished entries visited, in visit order.
pub fn verify_distinguished(
    w: &World,
    req: &DistinguishedRequest,
    resp: &DistinguishedResponse,
    recent: Recent,
) -> Result<Vec<u64>> {
    let n = w.n();
    let extra = w.check_head(&resp.full_tree_head, req.last, n);
    let mut c = Consumer::new(&resp.distinguished, n, req.last, w.retained(req.last));
    c.update_view()?;
    let rt = c.timestamp(n - 1)?;
    let mut walk = DWalk {
        stop: req.stop,
        recent,
        rightmost: rt,
        seen: Vec::new(),
    };
    walk.visit(&mut c, root(n)?, 0, rt)?;
    let roots = c.finish(&extra)?;
    check_roots(w, n, &extra, roots)?;
    Ok(walk.seen)
}

struct DWalk {
    stop: Option<u64>,
    recent: Recent,
    rightmost: u64,
    seen: Vec<u64>,
}

impl DWalk {
    fn visit(&mut self, c: &mut Consumer<'_>, x: u64, lt: u64, rt: u64) -> Result<()> {
        if !spans_window(lt, rt, WINDOW) {
            return Ok(());
        }
        let tx = c.timestamp(x)?;
        self.seen.push(x);
        if let Some(r) = right(x, c.n) {
            self.visit(c, r, tx, rt)?;
        }
        if self.stop.is_some_and(|s| x <= s) {
            return Ok(());
        }
        let is_recent = match self.recent {
            Recent::Within(ms) => self.rightmost.saturating_sub(tx) < ms,
            Recent::Rightmost(k) => (self.seen.iter().filter(|&&y| y > x).count() as u64) < k,
        };
        if !is_recent {
            return Ok(());
        }
        if let Some(l) = left(x) {
            self.visit(c, l, lt, tx)?;
        }
        Ok(())
    }
}

/// §14; returns the terminal entry of a provisional credential.
pub fn verify_credential(w: &World, cred: &Credential) -> Result<Option<u64>> {
    let g = cred.version;
    let mut keys = Keys::default();
    keys.absorb(&w.vrf_public, &cred.label, &base(g), &cred.binary_ladder)?;
    keys.target(&cred.label, g, &cred.opening, &cred.value);
    match &cred.body {
        CredentialBody::Standard { distinguished } => {
            let mut searches = Vec::new();
            let mut i = 0;
            let end = drive(LadderKind::Search { target: g }, |v| {
                let r = distinguished
                    .results
                    .get(i)
                    .ok_or(Error::MalformedProof("short"))?;
                i += 1;
                let inc = r.outcome == PrefixSearchOutcome::Inclusion;
                searches.push(PrefixSearch {
                    vrf_output: *keys.outputs.get(&v).ok_or(Error::MalformedProof("vrf"))?,
                    commitment: if inc {
                        keys.commitments.get(&v).copied()
                    } else {
                        None
                    },
                });
                Ok(inc)
            })?;
            if i != distinguished.results.len() || end.above_target || end.below_target_missing {
                return Err(bad("standard credential ladder"));
            }
            let root = evaluate(&searches, distinguished)?;
            if root != w.prover.store().entry(cred.position)?.prefix_tree {
                return Err(bad("standard credential root"));
            }
            Ok(None)
        }
        CredentialBody::Provisional { tree_head, search } => {
            let n = tree_head.tree_size;
            if n <= cred.position {
                return Err(bad("head before position"));
            }
            let last = Some(cred.position + 1);
            let mut c = Consumer::new(search, n, last, w.retained(last));
            c.update_view()?;
            let terminal = greatest_search(&mut c, &keys, g)?;
            if terminal <= cred.position {
                return Err(bad("terminal not right of position"));
            }
            let (root, _) = c.finish(&[])?;
            for cfg in &w.configs {
                verify_tree_head(tree_head, cfg, &root)?;
            }
            Ok(Some(terminal))
        }
    }
}

pub fn verify_credential_update(
    w: &World,
    cred: &Credential,
    terminal: u64,
    upd: &CredentialUpdate,
) -> Result<()> {
    let CredentialBody::Provisional { tree_head, .. } = &cred.body else {
        return Err(bad("not provisional"));
    };
    let n0 = tree_head.tree_size;
    let q = upd.position;
    let expected_q = w
        .prover
        .distinguished_entries()?
        .into_iter()
        .find(|&x| x > terminal);
    if expected_q != Some(q) {
        return Err(bad("credential update position"));
    }
    let keys = known_keys(w, &cred.label, Some(cred.version));
    let retained = (n0 <= q + 1).then_some(n0);
    let mut c = Consumer::new(&upd.monitor, q + 1, retained, w.retained(retained));
    c.update_view()?;
    contact(
        &mut c,
        &keys,
        &[MonitorMapEntry {
            position: terminal,
            version: cred.version,
        }],
        None,
    )?;
    let (root, _) = c.finish(&[])?;
    if root != w.prover.root(q + 1)? {
        return Err(bad("credential update root"));
    }
    Ok(())
}
