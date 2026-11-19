// SPDX-License-Identifier: MIT
//! Shared by the `prover_*` tests: a log built from a seeded history, and a
//! reference consumer of its proofs built only on the verifier-side math
//! (`prefix_proof::evaluate`, `log_tree::verify_batch`, `ladder::drive`,
//! `implicit`), following the layout rules in the `prover` module docs.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use peachy_keytrans::commitment::commit;
use peachy_keytrans::head::{sign_auditor_tree_head, verify_tree_head};
use peachy_keytrans::implicit::{ancestors, frontier, spans_window, update_view};
use peachy_keytrans::ladder::{drive, versions, LadderEnd, LadderKind};
use peachy_keytrans::log_tree::{full_subtrees, leaf_hash, verify_batch, BatchSpec};
use peachy_keytrans::prefix_proof::{evaluate, PrefixSearch};
use peachy_keytrans::prover::{LabelUpdate, MemoryStore, Prover, Storage};
use peachy_keytrans::suite::{CipherSuite, Hash, SecretKey, VrfOutput};
use peachy_keytrans::vrf::{VrfPublicKey, VrfSecretKey};
use peachy_keytrans::wire::{
    BinaryLadderStep, CombinedTreeProof, Configuration, FullTreeHead, KeyedAuditorTreeHead,
    LogEntry, ModeConfig, PrefixSearchOutcome, UpdateValue,
};
use peachy_keytrans::{Error, Result};

pub mod algorithms;

pub const WINDOW: u64 = 1_000;

/// A small deterministic generator (xorshift64*), so histories repeat.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

pub fn label(i: u64) -> Vec<u8> {
    format!("label-{i}").into_bytes()
}

/// A log with two auditors, both signing a head now and then.
pub struct World {
    pub prover: Prover<MemoryStore>,
    pub configs: Vec<Configuration>,
    pub auditors: Vec<SecretKey>,
    pub vrf_public: VrfPublicKey,
    pub vrf_secret: VrfSecretKey,
    pub now: u64,
    counter: u64,
}

impl World {
    pub fn new() -> Self {
        let log = SecretKey::from_seed(&[1; 32]);
        let vrf = VrfSecretKey::from_seed(&[2; 32]).unwrap();
        let vrf_copy = VrfSecretKey::from_seed(&[2; 32]).unwrap();
        let auditors = vec![
            SecretKey::from_seed(&[3; 32]),
            SecretKey::from_seed(&[4; 32]),
        ];
        let configs: Vec<Configuration> = auditors
            .iter()
            .map(|a| Configuration {
                ciphersuite: CipherSuite::Kt128Sha256Ed25519,
                signature_public_key: log.public_key().to_bytes().to_vec(),
                vrf_public_key: vrf.public_key().to_bytes().to_vec(),
                mode: ModeConfig::ThirdPartyAuditing {
                    max_auditor_lag: 10 * WINDOW,
                    auditor_start_pos: 0,
                    auditor_public_key: a.public_key().to_bytes().to_vec(),
                },
                max_ahead: WINDOW,
                max_behind: WINDOW,
                reasonable_monitoring_window: WINDOW,
                maximum_lifetime: None,
            })
            .collect();
        let vrf_public = vrf.public_key();
        let prover = Prover::new(MemoryStore::new(), configs.clone(), log, vrf).unwrap();
        World {
            prover,
            configs,
            auditors,
            vrf_public,
            vrf_secret: vrf_copy,
            now: 10_000,
            counter: 0,
        }
    }

    /// Appends one entry with `updates` (label index, value tag), `gap`
    /// milliseconds after the previous one.
    pub fn append(&mut self, gap: u64, updates: &[u64]) {
        self.now += gap;
        let updates: Vec<LabelUpdate> = updates
            .iter()
            .map(|&i| {
                self.counter += 1;
                let mut opening = [0u8; 16];
                opening[..8].copy_from_slice(&self.counter.to_be_bytes());
                LabelUpdate {
                    label: label(i),
                    value: UpdateValue {
                        value: format!("value-{}", self.counter).into_bytes(),
                    },
                    opening,
                }
            })
            .collect();
        self.prover.append(self.now, &updates).unwrap();
    }

    /// Has auditor `which` sign the head at `size`.
    pub fn audit(&mut self, which: usize, size: u64) {
        let root = self.prover.root(size).unwrap();
        let ts = self.prover.store().entry(size - 1).unwrap().timestamp;
        let head =
            sign_auditor_tree_head(&self.auditors[which], &self.configs[which], ts, size, &root)
                .unwrap();
        self.prover
            .add_auditor_head(KeyedAuditorTreeHead {
                auditor_public_key: self.auditors[which].public_key().to_bytes().to_vec(),
                auditor_tree_head: head,
            })
            .unwrap();
    }

    /// A random history of `entries` entries over `labels` labels, with
    /// gaps from a tenth of a window to two windows, so distinguished
    /// entries come and go at every depth.
    pub fn random(seed: u64, entries: u64, labels: u64) -> Self {
        let mut w = World::new();
        let mut rng = Rng::new(seed);
        for i in 0..entries {
            let count = match rng.below(10) {
                0..=2 => 0,
                3..=7 => 1,
                _ => 1 + rng.below(3),
            };
            let updates: Vec<u64> = (0..count).map(|_| rng.below(labels)).collect();
            let gap = match rng.below(6) {
                0 => 2 * WINDOW,
                1 => WINDOW,
                _ => WINDOW / 10 + rng.below(WINDOW / 3),
            };
            w.append(gap, &updates);
            if i % 7 == 3 {
                let size = w.prover.tree_size().unwrap();
                let back = rng.below(size.min(4));
                w.audit((i % 2) as usize, size - back);
            }
        }
        w
    }

    pub fn n(&self) -> u64 {
        self.prover.tree_size().unwrap()
    }

    pub fn ts(&self, x: u64) -> u64 {
        self.prover.store().entry(x).unwrap().timestamp
    }

    /// Greatest version of `label` in entry `x`, from the log's records.
    pub fn greatest_at(&self, label: &[u8], x: u64) -> Option<u32> {
        let v = self.prover.store().label_versions(label).unwrap();
        let c = v.iter().filter(|r| r.position <= x).count();
        c.checked_sub(1).map(|c| c as u32)
    }

    pub fn first_position(&self, label: &[u8], version: u32) -> u64 {
        self.prover.store().label_versions(label).unwrap()[version as usize].position
    }

    pub fn output(&self, label: &[u8], v: u32) -> VrfOutput {
        self.vrf_secret.prove_label(label, v).unwrap().1
    }

    /// What a client that verified size `last` retained.
    pub fn retained(&self, last: Option<u64>) -> Retained {
        let mut r = Retained::default();
        if let Some(m) = last.filter(|&m| m > 0) {
            for x in frontier(m) {
                let e = self.prover.store().entry(x).unwrap();
                r.entries.insert(x, (e.timestamp, e.prefix_tree));
            }
            r.subtrees = full_subtrees(m)
                .into_iter()
                .map(|s| self.prover.store().log_node(s).unwrap())
                .collect();
        }
        r
    }

    /// The full tree head's extra sizes, checking its signatures.
    pub fn check_head(&self, head: &FullTreeHead, last: Option<u64>, n: u64) -> Vec<u64> {
        match head {
            FullTreeHead::Same => {
                assert_eq!(last, Some(n));
                vec![]
            }
            FullTreeHead::Updated {
                tree_head,
                auditor_tree_heads,
            } => {
                assert_eq!(tree_head.tree_size, n);
                let root = self.prover.root(n).unwrap();
                for c in &self.configs {
                    verify_tree_head(tree_head, c, &root).unwrap();
                }
                auditor_tree_heads
                    .iter()
                    .map(|h| h.auditor_tree_head.tree_size)
                    .collect()
            }
        }
    }
}

#[derive(Default, Clone)]
pub struct Retained {
    pub entries: BTreeMap<u64, (u64, Hash)>,
    pub subtrees: Vec<Hash>,
}

/// What a client knows about a label's versions: VRF outputs and
/// commitments.
#[derive(Default, Clone)]
pub struct Keys {
    pub outputs: BTreeMap<u32, VrfOutput>,
    pub commitments: BTreeMap<u32, Hash>,
}

impl Keys {
    /// Reads `steps` for `versions`, verifying each VRF proof.
    pub fn absorb(
        &mut self,
        vrf: &VrfPublicKey,
        label: &[u8],
        versions: &[u32],
        steps: &[BinaryLadderStep],
    ) -> Result<()> {
        if versions.len() != steps.len() {
            return Err(Error::MalformedProof("binary ladder of the wrong length"));
        }
        for (&v, s) in versions.iter().zip(steps) {
            let out = vrf.verify_label(label, v, &s.proof)?;
            self.outputs.insert(v, out);
            if let Some(c) = s.commitment {
                self.commitments.insert(v, c);
            }
        }
        Ok(())
    }

    pub fn target(&mut self, label: &[u8], v: u32, opening: &[u8; 16], value: &UpdateValue) {
        self.commitments
            .insert(v, commit(opening, label, v, value).unwrap());
    }
}

/// Lookups a ladder may skip, as the consumer tracks them.
#[derive(Default)]
pub struct Known {
    pub right_too: bool,
    included: BTreeMap<u32, BTreeSet<u64>>,
    excluded: BTreeMap<u32, BTreeSet<u64>>,
}

impl Known {
    pub fn both() -> Self {
        Known {
            right_too: true,
            ..Known::default()
        }
    }
    fn answer(&self, v: u32, x: u64) -> Option<bool> {
        if self
            .included
            .get(&v)
            .is_some_and(|s| s.range(..x).next().is_some())
        {
            return Some(true);
        }
        if self.right_too
            && self
                .excluded
                .get(&v)
                .is_some_and(|s| s.range(x + 1..).next().is_some())
        {
            return Some(false);
        }
        None
    }
    pub fn record(&mut self, v: u32, x: u64, inc: bool) {
        if inc {
            &mut self.included
        } else {
            &mut self.excluded
        }
        .entry(v)
        .or_default()
        .insert(x);
    }
}

/// The reference consumer of one CombinedTreeProof.
pub struct Consumer<'a> {
    pub proof: &'a CombinedTreeProof,
    pub n: u64,
    pub last: Option<u64>,
    retained: Retained,
    ts: BTreeMap<u64, u64>,
    listed: Vec<u64>,
    roots: BTreeMap<u64, Hash>,
    next_ts: usize,
    next_proof: usize,
}

impl<'a> Consumer<'a> {
    pub fn new(
        proof: &'a CombinedTreeProof,
        n: u64,
        last: Option<u64>,
        retained: Retained,
    ) -> Self {
        let mut ts = BTreeMap::new();
        for (x, (t, _)) in &retained.entries {
            ts.insert(*x, *t);
        }
        Consumer {
            proof,
            n,
            last,
            retained,
            ts,
            listed: Vec::new(),
            roots: BTreeMap::new(),
            next_ts: 0,
            next_proof: 0,
        }
    }

    pub fn timestamp(&mut self, x: u64) -> Result<u64> {
        if x >= self.n {
            return Err(Error::MalformedProof("entry outside the tree"));
        }
        if let Some(t) = self.ts.get(&x) {
            return Ok(*t);
        }
        let t = *self
            .proof
            .timestamps
            .get(self.next_ts)
            .ok_or(Error::MalformedProof("too few timestamps"))?;
        self.next_ts += 1;
        self.ts.insert(x, t);
        self.listed.push(x);
        Ok(t)
    }

    pub fn update_view(&mut self) -> Result<()> {
        for x in update_view(self.n, self.last)? {
            self.timestamp(x)?;
        }
        Ok(())
    }

    pub fn proofs_left(&self) -> bool {
        self.next_proof < self.proof.prefix_proofs.len()
    }

    /// One prefix proof at `x`: `decide(i, result)` names each search as
    /// the results are read; returns the searches' results.
    pub fn prefix(
        &mut self,
        x: u64,
        searches: &[PrefixSearch],
    ) -> Result<Vec<PrefixSearchOutcome>> {
        self.timestamp(x)?;
        let p = self
            .proof
            .prefix_proofs
            .get(self.next_proof)
            .ok_or(Error::MalformedProof("too few prefix proofs"))?;
        self.next_proof += 1;
        let root = evaluate(searches, p)?;
        self.root_at(x, root)?;
        Ok(p.results.iter().map(|r| r.outcome).collect())
    }

    fn root_at(&mut self, x: u64, root: Hash) -> Result<()> {
        if let Some((_, kept)) = self.retained.entries.get(&x) {
            if *kept != root {
                return Err(Error::ProofMismatch(
                    "prefix proof disagrees with a retained root",
                ));
            }
        }
        if let Some(prev) = self.roots.insert(x, root) {
            if prev != root {
                return Err(Error::ProofMismatch("two prefix proofs disagree"));
            }
        }
        Ok(())
    }

    /// A ladder at `x`: lookups answered by `known` are skipped, the rest
    /// come from the next prefix proof, in order.
    pub fn ladder(
        &mut self,
        x: u64,
        kind: LadderKind,
        keys: &Keys,
        mut known: Option<&mut Known>,
    ) -> Result<LadderEnd> {
        self.timestamp(x)?;
        let p = self
            .proof
            .prefix_proofs
            .get(self.next_proof)
            .ok_or(Error::MalformedProof("too few prefix proofs"))?
            .clone();
        self.next_proof += 1;
        let mut searches = Vec::new();
        let mut i = 0usize;
        let end = drive(kind, |v| {
            let inc =
                match known.as_ref().and_then(|k| k.answer(v, x)) {
                    Some(a) => a,
                    None => {
                        let r = p
                            .results
                            .get(i)
                            .ok_or(Error::MalformedProof("too few ladder results"))?;
                        i += 1;
                        let inc = r.outcome == PrefixSearchOutcome::Inclusion;
                        let out = *keys
                            .outputs
                            .get(&v)
                            .ok_or(Error::MalformedProof("no VRF output for a lookup"))?;
                        let commitment =
                            if inc {
                                Some(*keys.commitments.get(&v).ok_or(Error::MalformedProof(
                                    "no commitment for an inclusion",
                                ))?)
                            } else {
                                None
                            };
                        searches.push(PrefixSearch {
                            vrf_output: out,
                            commitment,
                        });
                        inc
                    }
                };
            if let Some(k) = known.as_mut() {
                k.record(v, x, inc);
            }
            Ok(inc)
        })?;
        if i != p.results.len() {
            return Err(Error::MalformedProof("too many ladder results"));
        }
        let root = evaluate(&searches, &p)?;
        self.root_at(x, root)?;
        Ok(end)
    }

    pub fn is_distinguished(&mut self, x: u64) -> Result<bool> {
        let mut path = ancestors(x, self.n)?;
        path.reverse();
        path.push(x);
        let mut lt = 0;
        let mut rt = self.timestamp(self.n - 1)?;
        for (i, &y) in path.iter().enumerate() {
            if !spans_window(lt, rt, WINDOW) {
                return Ok(false);
            }
            if y == x {
                return Ok(true);
            }
            let t = self.timestamp(y)?;
            match path.get(i + 1) {
                Some(&next) if next < y => rt = t,
                Some(_) => lt = t,
                None => {}
            }
        }
        Ok(false)
    }

    /// Checks every field was used exactly, and returns the root and the
    /// roots at `extra_sizes`.
    pub fn finish(self, extra_sizes: &[u64]) -> Result<(Hash, Vec<Hash>)> {
        if self.next_ts != self.proof.timestamps.len() {
            return Err(Error::MalformedProof("too many timestamps"));
        }
        if self.next_proof != self.proof.prefix_proofs.len() {
            return Err(Error::MalformedProof("too many prefix proofs"));
        }
        // Timestamps rise with position.
        let all: Vec<u64> = self.ts.values().copied().collect();
        if all.windows(2).any(|w| w[0] > w[1]) {
            return Err(Error::ProofMismatch("timestamps not monotonic"));
        }
        let mut unproved: Vec<u64> = self
            .listed
            .iter()
            .copied()
            .filter(|x| !self.roots.contains_key(x))
            .collect();
        unproved.sort_unstable();
        if unproved.len() != self.proof.prefix_roots.len() {
            return Err(Error::MalformedProof("wrong number of prefix roots"));
        }
        let mut roots = self.roots.clone();
        for (x, r) in unproved.iter().zip(&self.proof.prefix_roots) {
            roots.insert(*x, *r);
        }
        let leaves = self
            .listed
            .iter()
            .map(|&x| {
                let entry = LogEntry {
                    timestamp: self.ts[&x],
                    prefix_tree: roots[&x],
                };
                leaf_hash(&entry).map(|h| (x, h))
            })
            .collect::<Result<Vec<_>>>()?;
        let spec = BatchSpec {
            tree_size: self.n,
            leaves: self.listed.clone(),
            retained_size: self.last,
            extra_sizes: extra_sizes.to_vec(),
        };
        let out = verify_batch(
            &spec,
            &leaves,
            &self.retained.subtrees,
            &self.proof.inclusion,
        )?;
        Ok((out.root, out.extra_roots))
    }
}

/// Checks a finished consumer's roots against the log.
pub fn check_roots(w: &World, n: u64, extra: &[u64], got: (Hash, Vec<Hash>)) -> Result<()> {
    if got.0 != w.prover.root(n)? {
        return Err(Error::ProofMismatch("root differs from the log's"));
    }
    for (s, r) in extra.iter().zip(&got.1) {
        if *r != w.prover.root(*s)? {
            return Err(Error::ProofMismatch("auditor root differs"));
        }
    }
    Ok(())
}

/// Appendix B's base ladder.
pub fn base(t: u32) -> Vec<u32> {
    versions(LadderKind::Greatest, Some(t))
}
