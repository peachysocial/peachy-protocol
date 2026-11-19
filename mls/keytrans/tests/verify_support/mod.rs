// SPDX-License-Identifier: MIT
//! A toy log for the verifier's tests: a log tree, one in-memory prefix
//! tree per entry, and responses built by running the verifier's own
//! walkers over a `ProofRecorder`, which is how a log lays its proofs out.

#![allow(dead_code)]

use std::collections::BTreeMap;

use peachy_keytrans::commitment::commit;
use peachy_keytrans::head::{sign_auditor_tree_head, sign_tree_head};
use peachy_keytrans::implicit::ancestors;
use peachy_keytrans::ladder::{self, LadderKind};
use peachy_keytrans::log_tree::{leaf_hash, MemoryLog, Subtree};
use peachy_keytrans::prefix_proof::{bit, leaf_hash as prefix_leaf_hash, parent_hash, EMPTY};
use peachy_keytrans::suite::{Hash, Opening, SecretKey, VrfOutput};
use peachy_keytrans::verify::{
    base_ladder, AuditorKey, AuditorSlot, ClientState, Deployment, LogSource, OwnerPolicy,
    OwnerState, ProofRecorder, Recency, Walk,
};
use peachy_keytrans::vrf::VrfSecretKey;
use peachy_keytrans::wire::{
    BinaryLadderStep, Configuration, ContactMonitorRequest, ContactMonitorResponse, Credential,
    CredentialBody, CredentialUpdate, DistinguishedRequest, DistinguishedResponse, FullTreeHead,
    KeyedAuditorTreeHead, LabelValue, LogEntry, MonitorMapEntry, OwnerInitRequest,
    OwnerInitResponse, OwnerMonitorRequest, OwnerMonitorResponse, PrefixLeaf, PrefixProof,
    PrefixSearchOutcome, PrefixSearchResult, SearchRequest, SearchResponse, TreeHead, UpdateInfo,
    UpdateRequest, UpdateResponse, UpdateValue,
};
use peachy_keytrans::Result;

/// Milliseconds between entries.
pub const STEP: u64 = 1_000;
/// The reasonable monitoring window: about one distinguished entry every
/// four entries.
pub const WINDOW: u64 = 4_000;

/// A persistent prefix tree.
#[derive(Clone, Debug)]
pub enum Tree {
    Empty,
    Leaf(PrefixLeaf),
    Parent(Box<Tree>, Box<Tree>),
}

impl Tree {
    pub fn insert(self, leaf: PrefixLeaf, depth: usize) -> Tree {
        match self {
            Tree::Empty => Tree::Leaf(leaf),
            Tree::Leaf(other) if other.vrf_output == leaf.vrf_output => Tree::Leaf(leaf),
            Tree::Leaf(other) => {
                let parent = Tree::Parent(Box::new(Tree::Empty), Box::new(Tree::Empty));
                parent.insert(other, depth).insert(leaf, depth)
            }
            Tree::Parent(l, r) => {
                if bit(&leaf.vrf_output, depth) {
                    Tree::Parent(l, Box::new(r.insert(leaf, depth + 1)))
                } else {
                    Tree::Parent(Box::new(l.insert(leaf, depth + 1)), r)
                }
            }
        }
    }

    pub fn hash(&self) -> Hash {
        match self {
            Tree::Empty => EMPTY,
            Tree::Leaf(l) => prefix_leaf_hash(l),
            Tree::Parent(l, r) => parent_hash(&l.hash(), &r.hash()),
        }
    }

    pub fn contains(&self, key: &VrfOutput) -> bool {
        matches!(self.search(key).outcome, PrefixSearchOutcome::Inclusion)
    }

    fn search(&self, key: &VrfOutput) -> PrefixSearchResult {
        let mut node = self;
        let mut depth = 0u8;
        loop {
            match node {
                Tree::Empty => {
                    return PrefixSearchResult {
                        outcome: PrefixSearchOutcome::NonInclusionParent,
                        depth,
                    }
                }
                Tree::Leaf(l) if l.vrf_output == *key => {
                    return PrefixSearchResult {
                        outcome: PrefixSearchOutcome::Inclusion,
                        depth,
                    }
                }
                Tree::Leaf(l) => {
                    return PrefixSearchResult {
                        outcome: PrefixSearchOutcome::NonInclusionLeaf { leaf: *l },
                        depth,
                    }
                }
                Tree::Parent(l, r) => {
                    node = if bit(key, usize::from(depth)) { r } else { l };
                    depth += 1;
                }
            }
        }
    }

    pub fn prove(&self, keys: &[VrfOutput]) -> PrefixProof {
        let results = keys.iter().map(|k| self.search(k)).collect();
        let mut elements = Vec::new();
        self.copath(keys, 0, &mut elements);
        PrefixProof { results, elements }
    }

    fn copath(&self, keys: &[VrfOutput], depth: usize, out: &mut Vec<Hash>) {
        if keys.is_empty() {
            out.push(self.hash());
            return;
        }
        if let Tree::Parent(l, r) = self {
            let (right, left): (Vec<VrfOutput>, Vec<VrfOutput>) =
                keys.iter().partition(|k| bit(k, depth));
            l.copath(&left, depth + 1, out);
            r.copath(&right, depth + 1, out);
        }
    }
}

/// One version of a label in the toy log.
#[derive(Clone, Debug)]
pub struct Version {
    pub value: Vec<u8>,
    pub opening: Opening,
    pub position: u64,
}

/// The toy log.
pub struct ToyLog {
    pub seed: u8,
    pub vrf: VrfSecretKey,
    pub log_key: SecretKey,
    pub auditor_keys: Vec<SecretKey>,
    pub deployment: Deployment,
    pub tree: MemoryLog,
    pub entries: Vec<LogEntry>,
    pub prefix: Vec<Tree>,
    pub labels: BTreeMap<Vec<u8>, Vec<Version>>,
    /// Each auditor's head size; `None`: it follows the log.
    pub auditor_lag: Vec<Option<u64>>,
    /// Every leaf the next entry's prefix tree holds, by key.
    pub leaves: BTreeMap<VrfOutput, Hash>,
}

pub fn deployment(log: &SecretKey, vrf: &VrfSecretKey, auditors: &[SecretKey]) -> Deployment {
    Deployment {
        signature_public_key: log.public_key().to_bytes(),
        vrf_public_key: vrf.public_key().to_bytes(),
        max_ahead: 10 * STEP,
        max_behind: 100 * STEP,
        reasonable_monitoring_window: WINDOW,
        maximum_lifetime: None,
        recency: Recency::Count(8),
        auditors: auditors
            .iter()
            .map(|k| AuditorSlot {
                max_auditor_lag: 20 * STEP,
                key: AuditorKey::Pinned {
                    public_key: k.public_key().to_bytes(),
                    start_position: 0,
                },
            })
            .collect(),
    }
}

impl Clone for ToyLog {
    fn clone(&self) -> ToyLog {
        let fresh = ToyLog::new(self.seed, self.auditor_keys.len());
        ToyLog {
            seed: self.seed,
            vrf: fresh.vrf,
            log_key: fresh.log_key,
            auditor_keys: fresh.auditor_keys,
            deployment: self.deployment.clone(),
            tree: self.tree.clone(),
            entries: self.entries.clone(),
            prefix: self.prefix.clone(),
            labels: self.labels.clone(),
            auditor_lag: self.auditor_lag.clone(),
            leaves: self.leaves.clone(),
        }
    }
}

impl ToyLog {
    /// A log with `auditors` auditors and no entries.
    pub fn new(seed: u8, auditors: usize) -> ToyLog {
        let vrf = VrfSecretKey::from_seed(&[seed; 32]).unwrap();
        let log_key = SecretKey::from_seed(&[seed.wrapping_add(1); 32]);
        let auditor_keys: Vec<SecretKey> = (0..auditors)
            .map(|i| SecretKey::from_seed(&[seed.wrapping_add(2 + i as u8); 32]))
            .collect();
        let deployment = deployment(&log_key, &vrf, &auditor_keys);
        ToyLog {
            seed,
            vrf,
            log_key,
            auditor_keys,
            deployment,
            tree: MemoryLog::new(),
            entries: Vec::new(),
            prefix: Vec::new(),
            labels: BTreeMap::new(),
            auditor_lag: vec![None; auditors],
            leaves: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn key(&self, label: &[u8], version: u32) -> VrfOutput {
        self.vrf.prove_label(label, version).unwrap().1
    }

    pub fn commitment(&self, label: &[u8], version: u32) -> Option<Hash> {
        let v = self.labels.get(label)?.get(version as usize)?;
        Some(
            commit(
                &v.opening,
                label,
                version,
                &UpdateValue {
                    value: v.value.clone(),
                },
            )
            .unwrap(),
        )
    }

    /// Appends one entry at the next timestamp, creating the given versions.
    pub fn append(&mut self, updates: &[(&[u8], &[u8])]) -> u64 {
        let position = self.len();
        for (label, value) in updates {
            let versions = self.labels.entry(label.to_vec()).or_default();
            let version = versions.len() as u32;
            let mut opening = [0u8; 16];
            opening[0] = version as u8;
            opening[1] = position as u8;
            opening[2] = label.len() as u8;
            versions.push(Version {
                value: value.to_vec(),
                opening,
                position,
            });
            let commitment = commit(
                &opening,
                label,
                version,
                &UpdateValue {
                    value: value.to_vec(),
                },
            )
            .unwrap();
            let key = self.vrf.prove_label(label, version).unwrap().1;
            self.leaves.insert(key, commitment);
        }
        let mut tree = Tree::Empty;
        for (&vrf_output, &commitment) in &self.leaves {
            tree = tree.insert(
                PrefixLeaf {
                    vrf_output,
                    commitment,
                },
                0,
            );
        }
        let entry = LogEntry {
            timestamp: (position + 1) * STEP,
            prefix_tree: tree.hash(),
        };
        self.tree.push(leaf_hash(&entry).unwrap());
        self.entries.push(entry);
        self.prefix.push(tree);
        position
    }

    /// Misbehaves: entries from now on leave `version` of `label` out of
    /// their prefix trees, while the log goes on claiming it.
    pub fn drop_version(&mut self, label: &[u8], version: u32) {
        let key = self.key(label, version);
        self.leaves.remove(&key);
    }

    /// Appends `count` empty entries.
    pub fn idle(&mut self, count: u64) {
        for _ in 0..count {
            self.append(&[]);
        }
    }

    pub fn now(&self) -> u64 {
        self.entries.last().map_or(0, |e| e.timestamp)
    }

    /// The greatest version of `label` at `position`.
    pub fn greatest_at(&self, label: &[u8], position: u64) -> Option<u32> {
        let versions = self.labels.get(label)?;
        versions
            .iter()
            .rposition(|v| v.position <= position)
            .map(|i| i as u32)
    }

    pub fn configs(&self) -> Vec<Configuration> {
        self.auditor_keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                self.deployment
                    .configuration(i, &k.public_key().to_bytes(), 0)
                    .unwrap()
            })
            .collect()
    }

    pub fn tree_head(&mut self, n: u64) -> TreeHead {
        let root = self.tree.root(n).unwrap();
        sign_tree_head(&self.log_key, &self.configs(), n, &root).unwrap()
    }

    pub fn auditor_sizes(&self, n: u64) -> Vec<u64> {
        self.auditor_lag
            .iter()
            .map(|lag| n.saturating_sub(lag.unwrap_or(0)).max(1))
            .collect()
    }

    pub fn auditor_heads(&mut self, n: u64) -> Vec<KeyedAuditorTreeHead> {
        let configs = self.configs();
        let sizes = self.auditor_sizes(n);
        let mut out = Vec::new();
        for (i, size) in sizes.into_iter().enumerate() {
            let root = self.tree.root(size).unwrap();
            let ts = self.entries[size as usize - 1].timestamp;
            let head = sign_auditor_tree_head(&self.auditor_keys[i], &configs[i], ts, size, &root)
                .unwrap();
            out.push(KeyedAuditorTreeHead {
                auditor_public_key: self.auditor_keys[i].public_key().to_bytes().to_vec(),
                auditor_tree_head: head,
            });
        }
        out
    }

    /// The full tree head for a client at `last`, and the extra sizes its
    /// inclusion proof covers.
    pub fn full_head(&mut self, last: Option<u64>, n: u64) -> (FullTreeHead, Vec<u64>) {
        if last == Some(n) {
            return (FullTreeHead::Same, Vec::new());
        }
        let sizes = self.auditor_sizes(n);
        (
            FullTreeHead::Updated {
                tree_head: self.tree_head(n),
                auditor_tree_heads: self.auditor_heads(n),
            },
            sizes,
        )
    }

    pub fn source<'a>(&'a mut self, label: &'a [u8]) -> Source<'a> {
        Source { log: self, label }
    }

    /// A binary ladder for `versions`, with each existing version's
    /// commitment when `commit_if` allows it.
    pub fn ladder_steps(
        &self,
        label: &[u8],
        versions: &[u32],
        commit_if: impl Fn(u32) -> bool,
    ) -> Vec<BinaryLadderStep> {
        versions
            .iter()
            .map(|&v| BinaryLadderStep {
                proof: self.vrf.prove_label(label, v).unwrap().0,
                commitment: if commit_if(v) {
                    self.commitment(label, v)
                } else {
                    None
                },
            })
            .collect()
    }

    // -----------------------------------------------------------------
    // Responses
    // -----------------------------------------------------------------

    pub fn search(
        &mut self,
        last: Option<u64>,
        label: &[u8],
        version: Option<u32>,
    ) -> (SearchRequest, SearchResponse) {
        let n = self.len();
        let request = SearchRequest {
            last,
            label: label.to_vec(),
            version,
        };
        let greatest = self.greatest_at(label, n - 1);
        let target = version.or(greatest).unwrap_or(0);
        let (full_tree_head, extra) = self.full_head(last, n);
        let window = self.deployment.reasonable_monitoring_window;
        let search = {
            let mut src = self.source(label);
            let mut rec = ProofRecorder::new(&mut src, last).unwrap();
            {
                let mut walk = Walk::new(&mut rec, n, window, None);
                walk.update_view(last).unwrap();
                if version.is_none() {
                    walk.greatest_search(target).unwrap();
                } else {
                    walk.fixed_search(target).unwrap();
                }
            }
            rec.finish(n, last, &extra).unwrap()
        };
        let exists = |v: u32| greatest.is_some_and(|g| v <= g);
        let binary_ladder = self.ladder_steps(label, &base_ladder(Some(target)), |v| {
            v != target && exists(v)
        });
        let (opening, value) = match self.labels.get(label).and_then(|l| l.get(target as usize)) {
            Some(v) => (v.opening, v.value.clone()),
            None => ([0; 16], Vec::new()),
        };
        let response = SearchResponse {
            full_tree_head,
            version: if version.is_none() {
                Some(target)
            } else {
                None
            },
            opening,
            value: UpdateValue { value },
            binary_ladder,
            search,
        };
        (request, response)
    }

    pub fn contact_monitor(&mut self, request: &ContactMonitorRequest) -> ContactMonitorResponse {
        let n = self.len();
        let last = request.last;
        let (full_tree_head, extra) = self.full_head(last, n);
        let window = self.deployment.reasonable_monitoring_window;
        let label = request.label.clone();
        let mut src = self.source(&label);
        let mut rec = ProofRecorder::new(&mut src, last).unwrap();
        {
            let mut walk = Walk::new(&mut rec, n, window, None);
            walk.update_view(last).unwrap();
            // A misbehaving log still answers, up to the ladder that fails.
            let _ = walk.contact_monitor(&request.entries, None);
        }
        ContactMonitorResponse {
            full_tree_head,
            monitor: rec.finish(n, last, &extra).unwrap(),
        }
    }

    pub fn owner_init(
        &mut self,
        last: Option<u64>,
        label: &[u8],
        start: u64,
    ) -> (OwnerInitRequest, OwnerInitResponse) {
        let n = self.len();
        let mut list = vec![start];
        list.extend(
            ancestors(start, n)
                .unwrap()
                .into_iter()
                .filter(|&a| a < start),
        );
        let mut greatest = Vec::new();
        for &x in &list {
            match self.greatest_at(label, x) {
                Some(g) => greatest.push(g),
                None => break,
            }
        }
        let mut versions = std::collections::BTreeSet::from([0u32]);
        for &g in &greatest {
            versions.extend(base_ladder(Some(g)));
        }
        let versions: Vec<u32> = versions.into_iter().collect();
        let top = greatest.first().copied();
        let binary_ladder = self.ladder_steps(label, &versions, |v| top.is_some_and(|g| v <= g));
        let (full_tree_head, extra) = self.full_head(last, n);
        let window = self.deployment.reasonable_monitoring_window;
        let init = {
            let mut src = self.source(label);
            let mut rec = ProofRecorder::new(&mut src, last).unwrap();
            {
                let mut walk = Walk::new(&mut rec, n, window, None);
                walk.update_view(last).unwrap();
                walk.owner_init(start, &greatest).unwrap();
            }
            rec.finish(n, last, &extra).unwrap()
        };
        (
            OwnerInitRequest {
                last,
                label: label.to_vec(),
                start,
            },
            OwnerInitResponse {
                full_tree_head,
                greatest_versions: greatest,
                binary_ladder,
                init,
            },
        )
    }

    pub fn owner_monitor(
        &mut self,
        request: &OwnerMonitorRequest,
        max_ladders: usize,
    ) -> OwnerMonitorResponse {
        let n = self.len();
        let last = request.last;
        let (full_tree_head, extra) = self.full_head(last, n);
        let window = self.deployment.reasonable_monitoring_window;
        let label = request.label.clone();
        let mut src = self.source(&label);
        let mut rec = ProofRecorder::new(&mut src, last)
            .unwrap()
            .with_owner_policy(OwnerPolicy {
                advertised: request.greatest_version,
                max_ladders,
            });
        {
            let mut walk = Walk::new(&mut rec, n, window, None);
            walk.update_view(last).unwrap();
            // A misbehaving log still answers, up to the ladder that fails.
            if walk
                .contact_monitor(&request.entries, Some(request.start))
                .is_ok()
            {
                let _ = walk.owner_monitor(request.start, &|_| None);
            }
        }
        OwnerMonitorResponse {
            full_tree_head,
            monitor: rec.finish(n, last, &extra).unwrap(),
        }
    }

    /// The responses to a passive update request: one per later entry that
    /// created versions, oldest first.
    pub fn updates(&mut self, request: &UpdateRequest) -> Vec<UpdateResponse> {
        let n = self.len();
        let label = request.label.clone();
        let versions = self.labels.get(&label).cloned().unwrap_or_default();
        let mut previous = request.greatest_version;
        let mut last = request.last;
        let mut out = Vec::new();
        loop {
            let first = previous.map_or(0, |g| g + 1) as usize;
            let Some(p) = versions.get(first).map(|v| v.position) else {
                break;
            };
            let new: Vec<u32> = (first..versions.len())
                .filter(|&v| versions[v].position == p)
                .map(|v| v as u32)
                .collect();
            let g_new = *new.last().unwrap();
            let mut wanted: std::collections::BTreeSet<u32> =
                base_ladder(Some(g_new)).into_iter().collect();
            if new.len() > 1 {
                wanted.extend(&new);
            }
            match previous {
                Some(g) => base_ladder(Some(g)).iter().for_each(|v| {
                    wanted.remove(v);
                }),
                None => {
                    wanted.remove(&0);
                }
            }
            let wanted: Vec<u32> = wanted.into_iter().collect();
            let binary_ladder =
                self.ladder_steps(&label, &wanted, |v| previous.is_some_and(|g| v <= g));
            let (full_tree_head, extra) = self.full_head(last, n);
            let window = self.deployment.reasonable_monitoring_window;
            let claims = peachy_keytrans::verify::UpdateClaims {
                position: p,
                previous_greatest: previous,
                new_versions: &new,
            };
            let update = {
                let mut src = self.source(&label);
                let mut rec = ProofRecorder::new(&mut src, last).unwrap();
                {
                    let mut walk = Walk::new(&mut rec, n, window, None);
                    walk.update_view(last).unwrap();
                    walk.update(&claims).unwrap();
                }
                rec.finish(n, last, &extra).unwrap()
            };
            out.push(UpdateResponse {
                full_tree_head,
                position: p,
                values: new
                    .iter()
                    .map(|&v| LabelValue {
                        value: versions[v as usize].value.clone(),
                    })
                    .collect(),
                info: new
                    .iter()
                    .map(|&v| UpdateInfo {
                        opening: versions[v as usize].opening,
                    })
                    .collect(),
                binary_ladder,
                update,
            });
            previous = Some(g_new);
            last = Some(n);
        }
        out
    }

    pub fn distinguished(&mut self, request: &DistinguishedRequest) -> DistinguishedResponse {
        let n = self.len();
        let last = request.last;
        let (full_tree_head, extra) = self.full_head(last, n);
        let window = self.deployment.reasonable_monitoring_window;
        let recency = self.deployment.recency;
        let mut src = self.source(b"");
        let mut rec = ProofRecorder::new(&mut src, last).unwrap();
        {
            let mut walk = Walk::new(&mut rec, n, window, None);
            walk.update_view(last).unwrap();
            walk.distinguished(request.stop, recency).unwrap();
        }
        DistinguishedResponse {
            full_tree_head,
            distinguished: rec.finish(n, last, &extra).unwrap(),
        }
    }

    /// A transparency proof for `label` anchored at `position`.
    pub fn credential(&mut self, label: &[u8], position: u64) -> Credential {
        let n = self.len();
        let version = self.greatest_at(label, n - 1).unwrap();
        let window = self.deployment.reasonable_monitoring_window;
        let standard = self.greatest_at(label, position) == Some(version);
        let body = if standard {
            let mut src = self.source(label);
            let mut rec = ProofRecorder::new(&mut src, Some(position + 1)).unwrap();
            {
                let mut walk = Walk::new(&mut rec, position + 1, window, None);
                walk.ladder(position, LadderKind::Search { target: version }, false)
                    .unwrap();
            }
            let proof = rec.finish(position + 1, Some(position + 1), &[]).unwrap();
            CredentialBody::Standard {
                distinguished: proof.prefix_proofs[0].clone(),
            }
        } else {
            let search = {
                let mut src = self.source(label);
                let mut rec = ProofRecorder::new(&mut src, Some(position + 1)).unwrap();
                {
                    let mut walk = Walk::new(&mut rec, n, window, None);
                    walk.update_view(Some(position + 1)).unwrap();
                    walk.greatest_search(version).unwrap();
                }
                rec.finish(n, Some(position + 1), &[]).unwrap()
            };
            CredentialBody::Provisional {
                tree_head: self.tree_head(n),
                search,
            }
        };
        let v = &self.labels[label][version as usize];
        Credential {
            label: label.to_vec(),
            version,
            opening: v.opening,
            value: UpdateValue {
                value: v.value.clone(),
            },
            binary_ladder: self.ladder_steps(label, &base_ladder(Some(version)), |x| x < version),
            position,
            body,
        }
    }

    /// The update for a provisional proof whose tree had `n0` entries.
    pub fn credential_update(
        &mut self,
        label: &[u8],
        version: u32,
        terminal: u64,
        n0: u64,
        q: u64,
    ) -> CredentialUpdate {
        let window = self.deployment.reasonable_monitoring_window;
        // The tree of q + 1 entries builds on the credential's only when it
        // contains it.
        let retained = (n0 <= q + 1).then_some(n0);
        let mut src = self.source(label);
        let mut rec = ProofRecorder::new(&mut src, retained).unwrap();
        {
            let mut walk = Walk::new(&mut rec, q + 1, window, None);
            walk.update_view(retained).unwrap();
            walk.contact_monitor(
                &[MonitorMapEntry {
                    position: terminal,
                    version,
                }],
                None,
            )
            .unwrap();
        }
        CredentialUpdate {
            position: q,
            monitor: rec.finish(q + 1, retained, &[]).unwrap(),
        }
    }
}

/// The log as a [`LogSource`] for one label.
pub struct Source<'a> {
    log: &'a mut ToyLog,
    label: &'a [u8],
}

impl LogSource for Source<'_> {
    fn log_entry(&mut self, position: u64) -> Result<LogEntry> {
        Ok(self.log.entries[position as usize])
    }

    fn includes(&mut self, position: u64, version: u32) -> Result<bool> {
        let key = self.log.key(self.label, version);
        Ok(self.log.prefix[position as usize].contains(&key))
    }

    fn greatest(&mut self, position: u64) -> Result<Option<u32>> {
        Ok(self.log.greatest_at(self.label, position))
    }

    fn prefix_proof(&mut self, position: u64, versions: &[u32]) -> Result<PrefixProof> {
        let keys: Vec<VrfOutput> = versions
            .iter()
            .map(|&v| self.log.key(self.label, v))
            .collect();
        Ok(self.log.prefix[position as usize].prove(&keys))
    }

    fn subtree(&mut self, subtree: Subtree) -> Result<Hash> {
        self.log.tree.subtree(subtree)
    }
}

/// Verifies every response a fresh client needs to reach the log's tip,
/// returning its state.
pub fn synced(log: &mut ToyLog) -> (peachy_keytrans::verify::Verifier, ClientState) {
    let verifier = peachy_keytrans::verify::Verifier::new(log.deployment.clone()).unwrap();
    let mut state = ClientState::new();
    let request = state.distinguished_request();
    let response = log.distinguished(&request);
    verifier
        .verify_distinguished(&mut state, &request, &response, log.now())
        .unwrap();
    (verifier, state)
}

/// The versions a ladder for `target` would look up when the greatest is
/// `greatest` (handy in assertions).
pub fn ladder_versions(target: u32, greatest: Option<u32>) -> Vec<u32> {
    ladder::versions(LadderKind::Search { target }, greatest)
}

/// An owner's state after initialization at `start`, verified.
pub fn owner(
    log: &mut ToyLog,
    verifier: &peachy_keytrans::verify::Verifier,
    state: &mut ClientState,
    label: &[u8],
    start: u64,
) -> OwnerState {
    let (request, response) = log.owner_init(state.last(), label, start);
    verifier
        .verify_owner_init(state, &request, &response, log.now())
        .unwrap()
}
