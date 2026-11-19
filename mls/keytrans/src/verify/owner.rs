// SPDX-License-Identifier: MIT
//! A label owner's operations: owner initialization (draft §13.3), owner
//! monitoring (§13.4) and label updates (§13.5).

use std::collections::BTreeSet;

use crate::verify::error::{VerifyError, VerifyResult};
use crate::verify::search::{add_entry, commitment_to, ladder_table};
use crate::verify::session::{commit as commit_view, run, Response};
use crate::verify::state::{ClientState, Insertion, OwnerState};
use crate::verify::walk::{base_ladder, UpdateClaims};
use crate::verify::Verifier;
use crate::wire::{
    LabelValue, OwnerInitRequest, OwnerInitResponse, OwnerMonitorRequest, OwnerMonitorResponse,
    UpdateRequest, UpdateResponse, UpdateValue,
};

/// A verified owner monitoring response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerMonitorResult {
    /// The distinguished entries whose ladders this response verified,
    /// ascending.
    pub verified: Vec<u64>,
    /// Whether the owner has now verified the rightmost distinguished
    /// entry. While not, the client asks again; if a response verifies
    /// nothing new, the log holds versions the owner has not learned of
    /// and the client sends an update request with no values first.
    pub caught_up: bool,
}

/// A verified label update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateResult {
    /// The entry the versions were inserted at.
    pub position: u64,
    /// The versions created there, ascending, with their values.
    pub created: Vec<(u32, Vec<u8>)>,
    /// Whether they are the values the request asked for (the response's
    /// `values` was empty). When not, the request's values were disregarded
    /// and stay pending.
    pub applied: bool,
}

impl OwnerState {
    /// The owner monitoring request for this state (§13.4).
    pub fn monitor_request(&self, state: &ClientState) -> OwnerMonitorRequest {
        OwnerMonitorRequest {
            last: state.last(),
            label: self.label.clone(),
            entries: self.contact_map.clone(),
            start: self.start,
            greatest_version: self.greatest(),
        }
    }

    /// The update request that creates `values` as the next versions, or
    /// learns of versions the log holds beyond the owner's when `values` is
    /// empty (§13.5).
    pub fn update_request(&self, state: &ClientState, values: Vec<LabelValue>) -> UpdateRequest {
        UpdateRequest {
            last: state.last(),
            label: self.label.clone(),
            greatest_version: self.greatest(),
            values,
        }
    }

    /// The request a further `UpdateResponse` to the same request is
    /// verified against, once `response` verified (§13.5): the client's new
    /// `last`, the owner's new greatest version, and the request's values
    /// until a response says they were created.
    pub fn follow_on_request(
        &self,
        state: &ClientState,
        request: &UpdateRequest,
        response: &UpdateResponse,
    ) -> UpdateRequest {
        let values = if response.values.is_empty() {
            Vec::new()
        } else {
            request.values.clone()
        };
        self.update_request(state, values)
    }

    /// Drops insertions that monitoring has verified past, keeping the last
    /// one at or before `start`.
    fn compact(&mut self) {
        let start = self.start;
        let keep_from = self
            .insertions
            .iter()
            .rposition(|i| i.position <= start)
            .unwrap_or(0);
        self.insertions.drain(..keep_from);
    }
}

impl Verifier {
    /// Verifies an owner initialization response (§13.3) and returns the
    /// owner's state for the label. Versions created after `start` are then
    /// learned one update at a time with update requests that carry no
    /// values (§8.3).
    pub fn verify_owner_init(
        &self,
        state: &mut ClientState,
        request: &OwnerInitRequest,
        response: &OwnerInitResponse,
        now: u64,
    ) -> VerifyResult<OwnerState> {
        let label = &request.label;
        let greatest = &response.greatest_versions;
        if greatest.windows(2).any(|w| w[1] > w[0]) {
            return Err(VerifyError::Proof(
                "greatest versions not in descending order",
            ));
        }
        let mut versions: BTreeSet<u32> = BTreeSet::from([0]);
        for &g in greatest {
            versions.extend(base_ladder(Some(g)));
        }
        let versions: Vec<u32> = versions.into_iter().collect();
        let table = ladder_table(
            &self.vrf,
            label,
            &versions,
            &response.binary_ladder,
            None,
            greatest.first().copied(),
        )?;
        if greatest
            .iter()
            .any(|&g| table.get(g).and_then(|k| k.commitment).is_none())
        {
            return Err(VerifyError::Proof("no commitment for a claimed version"));
        }
        let start = request.start;
        let out = run(
            &self.deployment,
            state,
            Response {
                last: request.last,
                head: &response.full_tree_head,
                proof: &response.init,
                versions: &table,
                now,
            },
            |walk| {
                walk.owner_init(start, greatest)?;
                Ok(((), Vec::new()))
            },
        )?;
        commit_view(&self.deployment, state, out.view);
        Ok(OwnerState {
            label: label.clone(),
            start,
            insertions: vec![Insertion {
                position: start,
                greatest: greatest.first().copied(),
            }],
            versions: table,
            contact_map: Vec::new(),
        })
    }

    /// Verifies an owner monitoring response (§13.4) for `owner`, then moves
    /// `state` and `owner` on.
    pub fn verify_owner_monitor(
        &self,
        state: &mut ClientState,
        owner: &mut OwnerState,
        request: &OwnerMonitorRequest,
        response: &OwnerMonitorResponse,
        now: u64,
    ) -> VerifyResult<OwnerMonitorResult> {
        if request.label != owner.label
            || request.entries != owner.contact_map
            || request.start != owner.start
            || request.greatest_version != owner.greatest()
        {
            return Err(VerifyError::RequestMismatch(
                "the request is not for this owner state",
            ));
        }
        let start = owner.start;
        let expected = |x: u64| owner.expected_at(x);
        let out = run(
            &self.deployment,
            state,
            Response {
                last: request.last,
                head: &response.full_tree_head,
                proof: &response.monitor,
                versions: &owner.versions,
                now,
            },
            |walk| {
                let map = walk.contact_monitor(&request.entries, Some(start))?;
                let verified = walk.owner_monitor(start, &expected)?;
                Ok(((map, verified), Vec::new()))
            },
        )?;
        let rightmost = out.rightmost_distinguished(&self.deployment)?;
        let (map, verified) = out.value;
        commit_view(&self.deployment, state, out.view);
        owner.contact_map = map;
        if let Some(&last) = verified.last() {
            owner.start = last;
            owner.compact();
        }
        Ok(OwnerMonitorResult {
            caught_up: rightmost.is_none_or(|r| owner.start >= r),
            verified,
        })
    }

    /// Verifies one `UpdateResponse` (§13.5) to `request` for `owner`, then
    /// moves `state` and `owner` on. A further response to the same request
    /// is verified against [`OwnerState::follow_on_request`].
    pub fn verify_update(
        &self,
        state: &mut ClientState,
        owner: &mut OwnerState,
        request: &UpdateRequest,
        response: &UpdateResponse,
        now: u64,
    ) -> VerifyResult<UpdateResult> {
        let label = &owner.label;
        if request.label != *label || request.greatest_version != owner.greatest() {
            return Err(VerifyError::RequestMismatch(
                "the request is not for this owner state",
            ));
        }
        // Step 1, with one more condition: the insertion is also after
        // `start`. Owner monitoring has checked every entry up to `start`
        // and never looks at them again, and at a distinguished entry the
        // walk below leaves the new version's ladder to that monitoring, so
        // an update claimed at or before `start` would go unproven for good.
        // A genuine one always lands past what monitoring has covered.
        let position = response.position;
        if position <= owner.greatest_position() || position <= owner.start {
            return Err(VerifyError::Proof(
                "an update not after the previous insertion",
            ));
        }
        // Step 2.
        let applied = response.values.is_empty();
        let created = if applied {
            &request.values
        } else {
            &response.values
        };
        if created.is_empty() || response.info.len() != created.len() {
            return Err(VerifyError::Proof(
                "update information does not match the versions",
            ));
        }
        let previous = request.greatest_version;
        let first = match previous {
            Some(g) => g
                .checked_add(1)
                .ok_or(VerifyError::Proof("no version after the greatest"))?,
            None => 0,
        };
        let new_versions: Vec<u32> = (0..created.len())
            .map(|i| {
                u32::try_from(i)
                    .ok()
                    .and_then(|i| first.checked_add(i))
                    .ok_or(VerifyError::Proof("versions past the last"))
            })
            .collect::<VerifyResult<_>>()?;
        let g_new = *new_versions
            .last()
            .ok_or(VerifyError::Proof("an update with no new version"))?;
        // Step 4: the VRF proofs of §9.1.
        let mut wanted: BTreeSet<u32> = base_ladder(Some(g_new)).into_iter().collect();
        if new_versions.len() > 1 {
            wanted.extend(&new_versions);
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
        let shown = ladder_table(
            &self.vrf,
            label,
            &wanted,
            &response.binary_ladder,
            None,
            previous,
        )?;
        let mut table = owner.versions.clone();
        table.merge(&shown)?;
        for ((&v, value), info) in new_versions.iter().zip(created).zip(&response.info) {
            let vrf_output = table
                .get(v)
                .ok_or(VerifyError::Proof("no VRF output for a new version"))?
                .vrf_output;
            let commitment = commitment_to(
                &info.opening,
                label,
                v,
                &UpdateValue {
                    value: value.value.clone(),
                },
            )?;
            table.insert(v, vrf_output, Some(commitment))?;
        }
        // Step 5.
        let claims = UpdateClaims {
            position,
            previous_greatest: previous,
            new_versions: &new_versions,
        };
        let out = run(
            &self.deployment,
            state,
            Response {
                last: request.last,
                head: &response.full_tree_head,
                proof: &response.update,
                versions: &table,
                now,
            },
            |walk| Ok((walk.update(&claims)?, Vec::new())),
        )?;
        let distinguished = out.value;
        commit_view(&self.deployment, state, out.view);
        owner.versions = table;
        owner.insertions.push(Insertion {
            position,
            greatest: Some(g_new),
        });
        if !distinguished {
            add_entry(&mut owner.contact_map, position, g_new);
        }
        Ok(UpdateResult {
            position,
            created: new_versions
                .iter()
                .copied()
                .zip(created.iter().map(|v| v.value.clone()))
                .collect(),
            applied,
        })
    }
}
