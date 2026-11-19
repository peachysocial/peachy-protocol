// SPDX-License-Identifier: MIT
//! What the log sends its auditors (§15.2): one
//! [`AuditorUpdate`] per log entry.
//!
//! [`Prover::append`](super::Prover::append) returns each entry's update as
//! it appends; [`Prover::auditor_update`] rebuilds the update of any entry
//! from storage, for an auditor that has to catch up. The two are the same
//! bytes: `added` is the entry's new leaves sorted by VRF output, `removed`
//! is empty (this log never prunes), and `proof` searches the previous
//! entry's prefix tree (an empty tree for entry 0) for each added key, in
//! `added`'s order.

use super::storage::{Nodes, Storage};
use super::Prover;
use crate::error::{Error, Result};
use crate::prefix_proof::EMPTY;
use crate::prefix_tree::prove;
use crate::wire::AuditorUpdate;

impl<S: Storage> Prover<S> {
    /// The [`AuditorUpdate`] for the entry at `position`.
    pub fn auditor_update(&self, position: u64) -> Result<AuditorUpdate> {
        if position >= self.tree_size()? {
            return Err(Error::InvalidArgument("entry outside the log"));
        }
        let entry = self.store().entry(position)?;
        let previous_root = match position.checked_sub(1) {
            Some(p) => self.store().entry(p)?.prefix_tree,
            None => EMPTY,
        };
        let added = self.store().entry_added(position)?;
        let keys: Vec<_> = added.iter().map(|l| l.vrf_output).collect();
        let proof = prove(&Nodes(self.store()), &previous_root, &keys)?;
        Ok(AuditorUpdate {
            timestamp: entry.timestamp,
            added,
            removed: Vec::new(),
            proof,
        })
    }
}
