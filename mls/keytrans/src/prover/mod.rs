// SPDX-License-Identifier: MIT
//! The log's side: appending entries and answering requests.
//!
//! Compiled with the `prover` feature (and in tests). It runs as wasm in
//! Node, so it takes time and randomness (timestamps, commitment openings)
//! as arguments, and reads and writes through the synchronous
//! [`Storage`] trait the host implements.
//!
//! The shared definitions it builds on: [`crate::wire`] (every message),
//! [`crate::log_tree`] (`prove_batch`), [`crate::implicit`] (`update_view`,
//! `distinguished_entries`), [`crate::ladder`] (`drive`),
//! [`crate::prefix_proof`] (what its prefix proofs evaluate to),
//! [`crate::commitment`], [`crate::vrf`] (`VrfSecretKey`) and
//! [`crate::head`] (`sign_tree_head`).
//!
//! # What a [`Prover`] does
//!
//! - [`Prover::append`] adds one log entry carrying a batch of new label
//!   versions, signs the new tree head, and returns the entry's
//!   [`AuditorUpdate`](crate::wire::AuditorUpdate) for the auditors
//!   (§15.2). [`Prover::heartbeat_due`] says when an empty entry is needed
//!   so distinguished entries keep coming about one reasonable monitoring
//!   window apart (§6.1).
//! - [`Prover::add_auditor_head`] keeps each auditor's latest head after
//!   checking its signature against the log.
//! - The request handlers, one per user operation of §13 and §14:
//!   [`Prover::search`], [`Prover::contact_monitor`], [`Prover::owner_init`],
//!   [`Prover::owner_monitor`], [`Prover::update`],
//!   [`Prover::distinguished`], [`Prover::credential`] and
//!   [`Prover::credential_update`].
//!
//! # How the proofs are laid out
//!
//! A [`CombinedTreeProof`](crate::wire::CombinedTreeProof) carries no
//! positions: the verifier runs the same algorithm and pops timestamps and
//! prefix proofs in the order it asks for them (Appendix C). Where the draft
//! leaves a choice, this prover makes the one below, and a verifier must
//! make the same. `N` is the served tree size and `last` the size the user
//! advertised.
//!
//! 1. **Timestamps.** Each entry's timestamp is listed at most once, the
//!    first time the algorithm asks for it. Entries on `frontier(last)` are
//!    retained by the user (§4.2) and never listed. Every proof starts with
//!    the timestamps of `update_view(N, last)`, for the tree size and
//!    retained size it is built with (for a provisional credential, `p + 1`
//!    retained; for a credential update, see [`Prover::credential_update`]).
//! 2. **A prefix proof brings its timestamp.** Asking for a ladder (or any
//!    prefix proof) at an entry first asks for that entry's timestamp, so
//!    each proof belongs to a leaf the inclusion proof covers or to a
//!    retained entry.
//! 3. **Is an entry distinguished?** Walk from the root to the entry, with
//!    bounds `(0, timestamp(N-1))`, narrowed at each step to the walked
//!    entry's timestamp on the side the walk leaves. At each entry: if the
//!    bounds are less than a window apart, it is not distinguished and the
//!    walk stops; if it is the entry asked about, it is; otherwise ask for
//!    its timestamp and step on. (§12.3.4 and §12.3.7: "from the root to
//!    the parent, stopping if a non-distinguished log entry is
//!    established".)
//! 4. **One proof per ladder.** Every ladder gives exactly one
//!    `PrefixProof` with its lookups in ladder order, minus those omitted.
//!    A ladder with every lookup omitted still gives a proof, with no
//!    results and the entry's prefix root as its one element.
//! 5. **Omissions.** Greatest-version search, and updates (§9.1 step 2 and
//!    step 4), omit an inclusion already shown at an entry to the left.
//!    Fixed-version search also omits a non-inclusion already shown at an
//!    entry to the right. Monitoring ladders (§8.2) and the owner's search
//!    ladders (§8.3, both algorithms) omit nothing.
//! 6. **`prefix_roots`** lists, in ascending position, every listed entry
//!    that got no prefix proof.
//! 7. **Inclusion** is `BatchSpec { tree_size: N, leaves: the listed
//!    entries, retained_size: last, extra_sizes: each auditor head's
//!    tree_size in the order the full tree head lists them }`; a `same`
//!    head carries no auditor heads, so no extra sizes.
//!
//! Each handler's module documents the order its algorithm asks in.

mod auditor_feed;
mod credential;
mod distinguished;
mod monitor;
mod proof;
mod search;
pub mod storage;
mod update;

pub use distinguished::Recent;
pub use storage::{MemoryStore, NewEntry, Storage, VersionRecord, WriteBatch};

use crate::commitment::commit;
use crate::error::{Error, Result};
use crate::head::{auditor_key, sign_tree_head, verify_auditor_tree_head};
use crate::implicit::{distinguished_entries, rightmost_distinguished};
use crate::log_tree::{full_subtrees, leaf_hash, parent_hash, root_from_full_subtrees, Subtree};
use crate::prefix_proof::EMPTY;
use crate::prefix_tree::{insert, prove};
use crate::suite::{Hash, Opening, SecretKey};
use crate::vrf::VrfSecretKey;
use crate::wire::{
    AuditorUpdate, Configuration, FullTreeHead, KeyedAuditorTreeHead, LogEntry, ModeConfig,
    PrefixLeaf, TreeHead, UpdateValue,
};
use storage::Nodes;

/// One new version of a label, for [`Prover::append`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelUpdate {
    /// The label (at most 255 bytes).
    pub label: Vec<u8>,
    /// Its new value.
    pub value: UpdateValue,
    /// The commitment opening, 16 random bytes the caller draws.
    pub opening: Opening,
}

/// What [`Prover::append`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    /// The new entry's position.
    pub position: u64,
    /// The version each update became, in the order given.
    pub versions: Vec<u32>,
    /// The entry as the auditors see it (§15.2).
    pub auditor_update: AuditorUpdate,
    /// The new signed tree head.
    pub tree_head: TreeHead,
}

/// The log: its keys, its configurations (one per auditor) and its storage.
pub struct Prover<S: Storage> {
    store: S,
    configs: Vec<Configuration>,
    log_key: SecretKey,
    vrf_key: VrfSecretKey,
    window: u64,
}

impl<S: Storage> Prover<S> {
    /// A prover over `store`. `configs` has one configuration per auditor,
    /// each in third-party auditing mode, all naming `log_key`'s and
    /// `vrf_key`'s public halves and one reasonable monitoring window.
    /// A maximum lifetime is refused: this prover never prunes.
    pub fn new(
        store: S,
        configs: Vec<Configuration>,
        log_key: SecretKey,
        vrf_key: VrfSecretKey,
    ) -> Result<Self> {
        let first = configs
            .first()
            .ok_or(Error::InvalidArgument("no configuration"))?;
        if configs.len() > 0xff {
            return Err(Error::InvalidArgument("too many auditors"));
        }
        let window = first.reasonable_monitoring_window;
        let log_public = log_key.public_key().to_bytes();
        let vrf_public = vrf_key.public_key().to_bytes();
        let mut auditors: Vec<&[u8]> = Vec::new();
        for c in &configs {
            c.ciphersuite.require_supported()?;
            if !matches!(c.mode, ModeConfig::ThirdPartyAuditing { .. }) {
                return Err(Error::InvalidArgument(
                    "configuration is not in third-party auditing mode",
                ));
            }
            if c.signature_public_key != log_public || c.vrf_public_key != vrf_public {
                return Err(Error::InvalidArgument("configuration names other log keys"));
            }
            if c.reasonable_monitoring_window != window {
                return Err(Error::InvalidArgument(
                    "configurations disagree on the monitoring window",
                ));
            }
            if c.maximum_lifetime.is_some() {
                return Err(Error::InvalidArgument(
                    "a maximum lifetime is not supported",
                ));
            }
            let a = auditor_key(c)?;
            if auditors.contains(&a) {
                return Err(Error::InvalidArgument("two configurations for one auditor"));
            }
            auditors.push(a);
        }
        Ok(Prover {
            store,
            configs,
            log_key,
            vrf_key,
            window,
        })
    }

    /// The storage.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The storage, mutably (for a host that also writes its own records).
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// The prover's configurations, one per auditor.
    pub fn configs(&self) -> &[Configuration] {
        &self.configs
    }

    pub(crate) fn window(&self) -> u64 {
        self.window
    }

    pub(crate) fn vrf_key(&self) -> &VrfSecretKey {
        &self.vrf_key
    }

    /// The number of log entries.
    pub fn tree_size(&self) -> Result<u64> {
        self.store.entry_count()
    }

    /// The log tree's root at `size` entries (at most the tree size).
    pub fn root(&self, size: u64) -> Result<Hash> {
        if size == 0 || size > self.tree_size()? {
            return Err(Error::InvalidArgument("size outside the log"));
        }
        let pairs = full_subtrees(size)
            .into_iter()
            .map(|s| self.store.log_node(s).map(|v| (s, v)))
            .collect::<Result<Vec<_>>>()?;
        root_from_full_subtrees(&pairs)
    }

    /// The signed head over the whole log.
    pub fn tree_head(&self) -> Result<TreeHead> {
        let n = self.tree_size()?;
        match self.store.tree_head()? {
            Some(h) if h.tree_size == n => Ok(h),
            Some(_) => Err(Error::Storage(
                "stored tree head is not at the log's size".into(),
            )),
            None => Err(Error::InvalidArgument("the log is empty")),
        }
    }

    /// Whether the log should append an entry, empty if nothing is pending,
    /// at time `now` (milliseconds): when it is empty, or its rightmost
    /// entry is a reasonable monitoring window old. Appending at least that
    /// often keeps distinguished entries about one window apart (§6.1).
    pub fn heartbeat_due(&self, now: u64) -> Result<bool> {
        let n = self.tree_size()?;
        if n == 0 {
            return Ok(true);
        }
        let last = self.store.entry(n - 1)?.timestamp;
        Ok(now.saturating_sub(last) >= self.window)
    }

    /// Appends one log entry at `timestamp` (milliseconds since the Unix
    /// epoch, at least the previous entry's) holding a new version for each
    /// update, in order; a label updated twice gets two consecutive
    /// versions. `updates` may be empty (a heartbeat). Writes everything in
    /// one [`WriteBatch`].
    pub fn append(&mut self, timestamp: u64, updates: &[LabelUpdate]) -> Result<Appended> {
        let n = self.tree_size()?;
        let previous_root = if n == 0 {
            EMPTY
        } else {
            let prev = self.store.entry(n - 1)?;
            if timestamp < prev.timestamp {
                return Err(Error::InvalidArgument(
                    "timestamp before the previous entry's",
                ));
            }
            prev.prefix_tree
        };
        if updates.len() > 0xffff {
            return Err(Error::InvalidArgument("too many updates in one entry"));
        }

        let mut next: std::collections::BTreeMap<&[u8], u32> = std::collections::BTreeMap::new();
        let mut records = Vec::with_capacity(updates.len());
        let mut versions = Vec::with_capacity(updates.len());
        for u in updates {
            if u.label.len() > 0xff {
                return Err(Error::InvalidArgument("label longer than 255 bytes"));
            }
            let version = match next.get(u.label.as_slice()) {
                Some(v) => *v,
                None => {
                    let have = self.store.label_versions(&u.label)?.len();
                    u32::try_from(have)
                        .map_err(|_| Error::InvalidArgument("label has every version"))?
                }
            };
            let after = version
                .checked_add(1)
                .ok_or(Error::InvalidArgument("label has every version"))?;
            next.insert(u.label.as_slice(), after);
            let (_, vrf_output) = self.vrf_key.prove_label(&u.label, version)?;
            let commitment = commit(&u.opening, &u.label, version, &u.value)?;
            versions.push(version);
            records.push(VersionRecord {
                label: u.label.clone(),
                version,
                position: n,
                opening: u.opening,
                value: u.value.clone(),
                vrf_output,
                commitment,
            });
        }

        let mut added: Vec<PrefixLeaf> = records.iter().map(VersionRecord::leaf).collect();
        added.sort();
        let keys: Vec<_> = added.iter().map(|l| l.vrf_output).collect();
        let proof = prove(&Nodes(&self.store), &previous_root, &keys)?;
        let insertion = insert(&Nodes(&self.store), &previous_root, &added)?;

        let entry = LogEntry {
            timestamp,
            prefix_tree: insertion.root,
        };
        let size = n + 1;
        let mut log_nodes = vec![(Subtree::leaf(n), leaf_hash(&entry)?)];
        let mut width = 2u64;
        while size.is_multiple_of(width) {
            let half = width / 2;
            let left = Subtree::new(size - width, half)?;
            let right = Subtree::new(size - half, half)?;
            let rv = log_nodes
                .last()
                .map(|(_, v)| *v)
                .ok_or_else(|| Error::Storage("log node".into()))?;
            let lv = self.store.log_node(left)?;
            let value = parent_hash(&lv, left.is_leaf(), &rv, right.is_leaf());
            log_nodes.push((Subtree::new(size - width, width)?, value));
            width = width
                .checked_mul(2)
                .ok_or(Error::InvalidArgument("log full"))?;
        }
        let pairs = full_subtrees(size)
            .into_iter()
            .map(|s| match log_nodes.iter().find(|(t, _)| *t == s) {
                Some((_, v)) => Ok((s, *v)),
                None => self.store.log_node(s).map(|v| (s, v)),
            })
            .collect::<Result<Vec<_>>>()?;
        let root = root_from_full_subtrees(&pairs)?;
        let tree_head = sign_tree_head(&self.log_key, &self.configs, size, &root)?;

        let auditor_update = AuditorUpdate {
            timestamp,
            added: added.clone(),
            removed: Vec::new(),
            proof,
        };
        self.store.apply(WriteBatch {
            entry: Some(NewEntry {
                position: n,
                entry,
                added,
            }),
            log_nodes,
            prefix_nodes: insertion.nodes,
            versions: records,
            tree_head: Some(tree_head.clone()),
            auditor_head: None,
        })?;
        Ok(Appended {
            position: n,
            versions,
            auditor_update,
            tree_head,
        })
    }

    /// Keeps an auditor's head, after checking that it names a configured
    /// auditor, covers a size the log has, carries that size's rightmost
    /// timestamp (§15.2 step 8), signs the log's root at that size, and is
    /// not older than the head already kept for that auditor.
    pub fn add_auditor_head(&mut self, head: KeyedAuditorTreeHead) -> Result<()> {
        let config = self
            .configs
            .iter()
            .find(|c| auditor_key(c).is_ok_and(|k| k == head.auditor_public_key))
            .ok_or(Error::InvalidArgument("head from an unknown auditor"))?;
        let h = &head.auditor_tree_head;
        let n = self.tree_size()?;
        if h.tree_size == 0 || h.tree_size > n {
            return Err(Error::InvalidArgument("auditor head outside the log"));
        }
        if self.store.entry(h.tree_size - 1)?.timestamp != h.timestamp {
            return Err(Error::InvalidArgument(
                "auditor head has the wrong timestamp",
            ));
        }
        verify_auditor_tree_head(h, config, &self.root(h.tree_size)?)?;
        if self.store.auditor_heads()?.iter().any(|k| {
            k.auditor_public_key == head.auditor_public_key
                && k.auditor_tree_head.tree_size > h.tree_size
        }) {
            return Err(Error::InvalidArgument(
                "auditor head older than the one kept",
            ));
        }
        self.store.apply(WriteBatch {
            auditor_head: Some(head),
            ..WriteBatch::default()
        })
    }

    /// The full tree head for a user who advertised `last`, and the tree
    /// sizes its auditor heads add to the inclusion proof.
    pub(crate) fn full_tree_head(
        &self,
        n: u64,
        last: Option<u64>,
    ) -> Result<(FullTreeHead, Vec<u64>)> {
        if last.is_some_and(|m| m > n) {
            return Err(Error::InvalidArgument("advertised size beyond the tree"));
        }
        if last == Some(n) {
            return Ok((FullTreeHead::Same, Vec::new()));
        }
        let tree_head = self.tree_head()?;
        let kept = self.store.auditor_heads()?;
        let mut auditor_tree_heads = Vec::new();
        for c in &self.configs {
            let key = auditor_key(c)?;
            if let Some(h) = kept.iter().find(|h| h.auditor_public_key == key) {
                if h.auditor_tree_head.tree_size <= n {
                    auditor_tree_heads.push(h.clone());
                }
            }
        }
        let sizes = auditor_tree_heads
            .iter()
            .map(|h| h.auditor_tree_head.tree_size)
            .collect();
        Ok((
            FullTreeHead::Updated {
                tree_head,
                auditor_tree_heads,
            },
            sizes,
        ))
    }

    /// Every distinguished entry, in position order (§6.1).
    pub fn distinguished_entries(&self) -> Result<Vec<u64>> {
        let n = self.tree_size()?;
        distinguished_entries(n, self.window, |x| self.store.entry(x).map(|e| e.timestamp))
    }

    /// The rightmost distinguished entry, if any.
    pub fn rightmost_distinguished(&self) -> Result<Option<u64>> {
        let n = self.tree_size()?;
        rightmost_distinguished(n, self.window, |x| self.store.entry(x).map(|e| e.timestamp))
    }

    /// The served size: the log must not be empty.
    pub(crate) fn served_size(&self) -> Result<u64> {
        let n = self.tree_size()?;
        if n == 0 {
            return Err(Error::InvalidArgument("the log is empty"));
        }
        Ok(n)
    }
}
