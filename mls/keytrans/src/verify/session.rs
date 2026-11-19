// SPDX-License-Identifier: MIT
//! One interactive response, from the tree head to the new view: the steps
//! every operation of draft §13 shares around its own algorithm.

use crate::implicit::{frontier, rightmost_distinguished};
use crate::suite::Hash;
use crate::verify::config::{Deployment, Recency};
use crate::verify::error::{VerifyError, VerifyResult};
use crate::verify::head::{check_clock, slot_of, verify_updated, UpdatedHead};
use crate::verify::reader::{Finished, ProofReader};
use crate::verify::state::{ClientState, VersionTable, View};
use crate::verify::walk::Walk;
use crate::wire::{CombinedTreeProof, FullTreeHead};

/// What a fully verified response established.
pub(crate) struct Outcome<T> {
    /// What the operation's algorithm returned.
    pub value: T,
    /// The proof as read.
    pub fin: Finished,
    /// The view to retain.
    pub view: View,
    /// The full subtrees at each tree size the operation asked for, in its
    /// order.
    pub body_full_subtrees: Vec<Vec<Hash>>,
}

impl<T> Outcome<T> {
    /// The rightmost distinguished entry of the new tree.
    pub fn rightmost_distinguished(&self, deployment: &Deployment) -> VerifyResult<Option<u64>> {
        let n = self.view.tree_size;
        Ok(rightmost_distinguished(
            n,
            deployment.reasonable_monitoring_window,
            |x| {
                self.fin.entries.get(&x).map(|e| e.timestamp).ok_or(
                    crate::error::Error::InvalidArgument("frontier entry unknown"),
                )
            },
        )?)
    }
}

/// The inputs every operation passes to [`run`].
pub(crate) struct Response<'p> {
    /// The request's `last`.
    pub last: Option<u64>,
    /// The response's `full_tree_head`.
    pub head: &'p FullTreeHead,
    /// The response's `CombinedTreeProof`.
    pub proof: &'p CombinedTreeProof,
    /// The VRF outputs and commitments the operation's lookups need.
    pub versions: &'p VersionTable,
    /// The current time, in milliseconds since the Unix epoch.
    pub now: u64,
}

/// The tree size a response is for (§11.4, before any signature).
fn tree_size(state: &ClientState, last: Option<u64>, head: &FullTreeHead) -> VerifyResult<u64> {
    if last != state.last() {
        return Err(VerifyError::RequestMismatch(
            "the request's last is not the client's tree size",
        ));
    }
    match head {
        FullTreeHead::Same => last.ok_or(VerifyError::UnadvertisedSame),
        FullTreeHead::Updated { tree_head, .. } => {
            let n = tree_head.tree_size;
            if n == 0 {
                return Err(VerifyError::EmptyTree);
            }
            if last.is_some_and(|m| n <= m) {
                return Err(VerifyError::HeadNotNewer);
            }
            Ok(n)
        }
    }
}

/// Runs an operation's algorithm (`body`, which returns its value and the
/// extra tree sizes whose full subtrees it needs) over a response, then
/// verifies the inclusion proof, the clock window and the tree head.
/// Changes nothing: the caller commits [`Outcome::view`] with [`commit`].
pub(crate) fn run<'p, T>(
    deployment: &Deployment,
    state: &ClientState,
    response: Response<'p>,
    body: impl FnOnce(&mut Walk<'_, ProofReader<'p>>) -> VerifyResult<(T, Vec<u64>)>,
) -> VerifyResult<Outcome<T>> {
    let last = response.last;
    let n = tree_size(state, last, response.head)?;
    let auditor_sizes: Vec<u64> = match response.head {
        FullTreeHead::Same => Vec::new(),
        FullTreeHead::Updated {
            auditor_tree_heads, ..
        } => {
            let mut sizes = Vec::with_capacity(auditor_tree_heads.len());
            for h in auditor_tree_heads {
                let size = h.auditor_tree_head.tree_size;
                if size == 0 || size > n {
                    return Err(match slot_of(deployment, state, &h.auditor_public_key) {
                        Some(slot) => VerifyError::AuditorAheadOfLog { slot },
                        None => VerifyError::Proof("an auditor head outside the tree"),
                    });
                }
                sizes.push(size);
            }
            sizes
        }
    };
    let previous = state.view.as_ref();
    let retained = previous.map(View::frontier_entries).unwrap_or_default();
    let mut reader = ProofReader::new(response.proof, retained, response.versions);
    let (value, body_sizes) = {
        let mut walk = Walk::new(
            &mut reader,
            n,
            deployment.reasonable_monitoring_window,
            deployment.maximum_lifetime,
        );
        walk.update_view(last)?;
        body(&mut walk)?
    };
    let mut extra = auditor_sizes.clone();
    extra.extend(&body_sizes);
    let retained_full = previous.map(|v| v.full_subtrees.as_slice()).unwrap_or(&[]);
    let fin = reader.finish(n, last, retained_full, &extra)?;
    let rightmost = fin
        .entries
        .get(&(n - 1))
        .map(|e| e.timestamp)
        .ok_or(VerifyError::Proof("no timestamp for the rightmost entry"))?;
    check_clock(deployment, rightmost, response.now)?;
    let frontier_entries = frontier(n)
        .into_iter()
        .map(|x| {
            fin.entries
                .get(&x)
                .copied()
                .ok_or(VerifyError::Proof("no timestamp for a frontier entry"))
        })
        .collect::<VerifyResult<Vec<_>>>()?;
    let view = match response.head {
        FullTreeHead::Same => previous.cloned().ok_or(VerifyError::UnadvertisedSame)?,
        FullTreeHead::Updated {
            tree_head,
            auditor_tree_heads,
        } => {
            let k = auditor_sizes.len();
            let slots = verify_updated(
                deployment,
                state,
                previous,
                &UpdatedHead {
                    tree_head,
                    auditor_tree_heads,
                    root: fin.roots.root,
                    auditor_roots: &fin.roots.extra_roots[..k],
                    rightmost_timestamp: rightmost,
                },
            )?;
            View {
                tree_size: n,
                full_subtrees: fin.roots.full_subtrees.clone(),
                frontier: frontier_entries,
                tree_head: tree_head.clone(),
                auditor_tree_heads: auditor_tree_heads.clone(),
                slots,
            }
        }
    };
    let body_full_subtrees = fin
        .roots
        .extra_full_subtrees
        .get(auditor_sizes.len()..)
        .unwrap_or(&[])
        .to_vec();
    Ok(Outcome {
        value,
        fin,
        view,
        body_full_subtrees,
    })
}

/// Retains a verified view, dropping the distinguished entries a windowed
/// definition of recent no longer covers.
pub(crate) fn commit(deployment: &Deployment, state: &mut ClientState, view: View) {
    if let Recency::Window(w) = deployment.recency {
        let rightmost = view.rightmost_timestamp();
        state
            .distinguished
            .retain(|d| rightmost.saturating_sub(d.entry.timestamp) < w);
    }
    state.view = Some(view);
}
