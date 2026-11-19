// SPDX-License-Identifier: MIT
//! Walking the recent distinguished entries (draft §10.1, §13.6), and what
//! a client keeps at each for transparency proofs (§14.2.1).

use crate::implicit::frontier;
use crate::log_tree::full_subtrees;
use crate::verify::config::Recency;
use crate::verify::error::{VerifyError, VerifyResult};
use crate::verify::session::{commit as commit_view, run, Response};
use crate::verify::state::{ClientState, DistinguishedEntry, VersionTable};
use crate::verify::Verifier;
use crate::wire::{DistinguishedRequest, DistinguishedResponse};

impl ClientState {
    /// The request that walks the distinguished entries newer than the
    /// newest this client holds.
    pub fn distinguished_request(&self) -> DistinguishedRequest {
        DistinguishedRequest {
            last: self.last(),
            stop: self.distinguished.last().map(|d| d.position),
        }
    }
}

impl Verifier {
    /// Verifies a distinguished walk (§13.6), then moves `state` to its tree
    /// head and retains each recent distinguished entry it found with the
    /// log tree as it stood there. Returns the entries found, ascending.
    pub fn verify_distinguished(
        &self,
        state: &mut ClientState,
        request: &DistinguishedRequest,
        response: &DistinguishedResponse,
        now: u64,
    ) -> VerifyResult<Vec<u64>> {
        let retained: Vec<u64> = state.last().map(frontier).unwrap_or_default();
        let recency = self.deployment.recency;
        let empty = VersionTable::default();
        let out = run(
            &self.deployment,
            state,
            Response {
                last: request.last,
                head: &response.full_tree_head,
                proof: &response.distinguished,
                versions: &empty,
                now,
            },
            |walk| {
                let found = walk.distinguished(request.stop, recency)?;
                // A listed entry's tree comes out of the inclusion proof at
                // one more size, which adds no element to it; a retained
                // one's is a prefix of the retained view's.
                let sizes = found
                    .iter()
                    .filter(|d| !retained.contains(d))
                    .map(|d| d + 1)
                    .collect();
                Ok((found, sizes))
            },
        )?;
        let mut found = out.value.clone();
        found.reverse();
        let previous = state.view.as_ref();
        let mut sizes = out.body_full_subtrees.iter();
        let mut kept = Vec::with_capacity(found.len());
        // `found` came right to left, and the sizes in that order.
        for &d in out.value.iter() {
            let subtrees = if retained.contains(&d) {
                let view = previous.ok_or(VerifyError::NoView)?;
                let count = full_subtrees(d + 1).len();
                view.full_subtrees
                    .get(..count)
                    .ok_or(VerifyError::Proof("a retained tree too small"))?
                    .to_vec()
            } else {
                sizes
                    .next()
                    .cloned()
                    .ok_or(VerifyError::Proof("no subtrees for a distinguished entry"))?
            };
            let entries = frontier(d + 1)
                .into_iter()
                .map(|x| {
                    out.fin.entries.get(&x).copied().ok_or(VerifyError::Proof(
                        "no entry on a distinguished tree's frontier",
                    ))
                })
                .collect::<VerifyResult<Vec<_>>>()?;
            let entry = *entries
                .last()
                .ok_or(VerifyError::Proof("an empty frontier"))?;
            kept.push(DistinguishedEntry {
                position: d,
                entry,
                full_subtrees: subtrees,
                frontier: entries,
            });
        }
        let mut merged = state.distinguished.clone();
        for k in kept {
            match merged.iter().position(|m| m.position == k.position) {
                Some(i) => {
                    if merged[i] != k {
                        return Err(VerifyError::Inconsistent(
                            "a distinguished entry differs from the one retained",
                        ));
                    }
                }
                None => merged.push(k),
            }
        }
        merged.sort_by_key(|m| m.position);
        if let Recency::Count(c) = recency {
            let excess = merged.len().saturating_sub(c as usize);
            merged.drain(..excess);
        }
        state.distinguished = merged;
        commit_view(&self.deployment, state, out.view);
        Ok(found)
    }
}
