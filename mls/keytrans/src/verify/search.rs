// SPDX-License-Identifier: MIT
//! Search (draft §13.1) and contact monitoring (§13.2).

use std::collections::BTreeMap;

use crate::commitment::commit;
use crate::suite::{Hash, Opening};
use crate::verify::error::{VerifyError, VerifyResult};
use crate::verify::session::{commit as commit_view, run, Response};
use crate::verify::state::{ClientState, ContactMonitor, VersionTable};
use crate::verify::walk::{base_ladder, FixedEnd};
use crate::verify::Verifier;
use crate::vrf::VrfPublicKey;
use crate::wire::{
    BinaryLadderStep, ContactMonitorRequest, ContactMonitorResponse, MonitorMapEntry,
    SearchRequest, SearchResponse, UpdateValue,
};

/// Checks a `binary_ladder` against the `versions` it must list, in order,
/// and returns what it shows. A step may carry a commitment only for a
/// version at most `commitments_up_to` (none at all for `None`). `target`,
/// when given, is a version whose commitment the caller computed: its step
/// must carry none.
pub(crate) fn ladder_table(
    vrf: &VrfPublicKey,
    label: &[u8],
    versions: &[u32],
    steps: &[BinaryLadderStep],
    target: Option<(u32, Hash)>,
    commitments_up_to: Option<u32>,
) -> VerifyResult<VersionTable> {
    if versions.len() != steps.len() {
        return Err(VerifyError::Proof("a binary ladder of the wrong length"));
    }
    let mut table = VersionTable::default();
    for (&v, step) in versions.iter().zip(steps) {
        let vrf_output = vrf
            .verify_label(label, v, &step.proof)
            .map_err(|_| VerifyError::BadVrfProof)?;
        if step.commitment.is_some() && commitments_up_to.is_none_or(|g| v > g) {
            return Err(VerifyError::Proof(
                "a commitment for a version that cannot exist",
            ));
        }
        let commitment = match target {
            Some((t, c)) if t == v => {
                if step.commitment.is_some() {
                    return Err(VerifyError::Proof("a commitment for the target version"));
                }
                Some(c)
            }
            _ => step.commitment,
        };
        table.insert(v, vrf_output, commitment)?;
    }
    if target.is_some_and(|(t, _)| table.get(t).is_none()) {
        return Err(VerifyError::Proof("the binary ladder skips the target"));
    }
    Ok(table)
}

/// The commitment to `value` as `label`'s `version`.
pub(crate) fn commitment_to(
    opening: &Opening,
    label: &[u8],
    version: u32,
    value: &UpdateValue,
) -> VerifyResult<Hash> {
    commit(opening, label, version, value).map_err(|_| VerifyError::BadCommitment)
}

/// A verified search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    /// The version found: the greatest, or the one asked for.
    pub version: u32,
    /// Its value.
    pub value: Vec<u8>,
    /// The search's terminal entry.
    pub terminal: u64,
    /// The monitoring map the search starts (§8.2); merge it into any map
    /// already held for the label with [`ContactMonitor::merge`].
    pub monitor: ContactMonitor,
}

impl ContactMonitor {
    /// A map with nothing in it.
    pub fn new(label: Vec<u8>) -> Self {
        ContactMonitor {
            label,
            entries: Vec::new(),
            versions: VersionTable::default(),
        }
    }

    /// Adds `version` at `position`. One position keeps its greatest version
    /// and one version its rightmost position, so a map never lists the
    /// same version twice (§13.2).
    pub fn add(&mut self, position: u64, version: u32) {
        add_entry(&mut self.entries, position, version);
    }

    /// Merges a map for the same label into this one.
    pub fn merge(&mut self, other: &ContactMonitor) -> VerifyResult<()> {
        if other.label != self.label {
            return Err(VerifyError::RequestMismatch("maps for different labels"));
        }
        self.versions.merge(&other.versions)?;
        for e in &other.entries {
            self.add(e.position, e.version);
        }
        Ok(())
    }

    /// The request that monitors this map.
    pub fn request(&self, state: &ClientState) -> ContactMonitorRequest {
        ContactMonitorRequest {
            last: state.last(),
            label: self.label.clone(),
            entries: self.entries.clone(),
        }
    }
}

/// [`ContactMonitor::add`] on a bare map.
pub(crate) fn add_entry(entries: &mut Vec<MonitorMapEntry>, position: u64, version: u32) {
    let mut by_version: BTreeMap<u32, u64> = BTreeMap::new();
    let all = entries
        .iter()
        .copied()
        .chain([MonitorMapEntry { position, version }]);
    for e in all {
        let p = by_version.entry(e.version).or_insert(e.position);
        *p = (*p).max(e.position);
    }
    let mut by_position: BTreeMap<u64, u32> = BTreeMap::new();
    for (v, p) in by_version {
        let kept = by_position.entry(p).or_insert(v);
        *kept = (*kept).max(v);
    }
    *entries = by_position
        .into_iter()
        .map(|(position, version)| MonitorMapEntry { position, version })
        .collect();
}

impl Verifier {
    /// Verifies a search response (§13.1) and, only when it verifies in
    /// full, moves `state` to its tree head. A version that is verifiably
    /// absent or expired fails as [`VerifyError::VersionNotFound`] or
    /// [`VerifyError::VersionExpired`] and leaves `state` as it was.
    pub fn verify_search(
        &self,
        state: &mut ClientState,
        request: &SearchRequest,
        response: &SearchResponse,
        now: u64,
    ) -> VerifyResult<SearchResult> {
        let label = &request.label;
        let (target, greatest) = match (request.version, response.version) {
            (Some(t), None) => (t, false),
            (None, Some(g)) => (g, true),
            _ => {
                return Err(VerifyError::RequestMismatch(
                    "a version is in both or neither of request and response",
                ))
            }
        };
        let target_commitment = commitment_to(&response.opening, label, target, &response.value)?;
        // A greatest-version search shows no version above the target.
        let commitments_up_to = if greatest {
            Some(target)
        } else {
            Some(u32::MAX)
        };
        let versions = ladder_table(
            &self.vrf,
            label,
            &base_ladder(Some(target)),
            &response.binary_ladder,
            Some((target, target_commitment)),
            commitments_up_to,
        )?;
        let out = run(
            &self.deployment,
            state,
            Response {
                last: request.last,
                head: &response.full_tree_head,
                proof: &response.search,
                versions: &versions,
                now,
            },
            |walk| {
                let end = if greatest {
                    FixedEnd::Found(walk.greatest_search(target)?)
                } else {
                    walk.fixed_search(target)?
                };
                Ok((end, Vec::new()))
            },
        )?;
        let terminal = match out.value {
            FixedEnd::Found(x) => x,
            FixedEnd::NotFound => return Err(VerifyError::VersionNotFound),
            FixedEnd::Expired => return Err(VerifyError::VersionExpired),
        };
        commit_view(&self.deployment, state, out.view);
        let mut monitor = ContactMonitor::new(label.clone());
        monitor.versions = versions;
        monitor.add(terminal, target);
        Ok(SearchResult {
            version: target,
            value: response.value.value.clone(),
            terminal,
            monitor,
        })
    }

    /// Verifies a contact monitoring response (§13.2) for `monitor`, then
    /// moves `state` to its tree head and `monitor` on.
    pub fn verify_contact_monitor(
        &self,
        state: &mut ClientState,
        monitor: &mut ContactMonitor,
        request: &ContactMonitorRequest,
        response: &ContactMonitorResponse,
        now: u64,
    ) -> VerifyResult<()> {
        if request.label != monitor.label || request.entries != monitor.entries {
            return Err(VerifyError::RequestMismatch(
                "the request is not for this monitoring map",
            ));
        }
        let out = run(
            &self.deployment,
            state,
            Response {
                last: request.last,
                head: &response.full_tree_head,
                proof: &response.monitor,
                versions: &monitor.versions,
                now,
            },
            |walk| Ok((walk.contact_monitor(&request.entries, None)?, Vec::new())),
        )?;
        commit_view(&self.deployment, state, out.view);
        monitor.entries = out.value;
        Ok(())
    }
}
