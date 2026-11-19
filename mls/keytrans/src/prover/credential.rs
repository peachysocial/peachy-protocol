// SPDX-License-Identifier: MIT
//! Credentials (§14): a label's greatest version, provable without asking
//! the log, anchored at a distinguished entry.
//!
//! - **Standard** (§14.1), when the greatest version is already the
//!   greatest in the distinguished entry at `position`: `distinguished` is
//!   that entry's search ladder with the version as target, omitting
//!   nothing.
//! - **Provisional** (§14.2) otherwise: the current signed head, and
//!   `search` built as a greatest-version search response for a user who
//!   advertised `position + 1` (its update view first), with no auditor
//!   heads, so no extra sizes in its inclusion proof.
//!
//! A provisional credential's [`CredentialUpdate`] (§14.2) names `q`, the
//! first distinguished entry to the right of the search's terminal entry,
//! and carries contact monitoring (§8.2) of `{terminal: version}` in the
//! tree of `q + 1` entries, for a user who retained the credential's tree
//! size `N0`: the timestamps of `update_view(q + 1, N0)` first (the walk
//! needs entry `q`'s timestamp), then §8.2 as in [`crate::prover`]'s
//! monitoring, with no extra sizes.
//!
//! The draft computes that proof "with a tree size of position+1" for a
//! user who retained `N0`, which only works when `q + 1 >= N0`. As the log
//! grows, an entry between the terminal entry and `N0 - 1` can become
//! distinguished, making `q + 1 < N0`; a user's retained subtrees of `N0`
//! cannot verify a smaller tree. Then the proof is built for a user who
//! retained nothing (`last` absent): every timestamp of `update_view(q + 1)`
//! listed, and the inclusion proof self-contained. Both sides know `q` and
//! `N0`, so both pick the same case.

use super::monitor::contact;
use super::proof::{Builder, Label};
use super::search::{greatest_search, search_steps};
use super::storage::Storage;
use super::Prover;
use crate::error::{Error, Result};
use crate::implicit::{frontier, rightmost_distinguished, root};
use crate::ladder::LadderKind;
use crate::wire::{Credential, CredentialBody, CredentialUpdate, MonitorMapEntry};

impl<S: Storage> Prover<S> {
    /// A credential for `label`'s greatest version, anchored at the
    /// distinguished entry at `position`; `None` if the label has no
    /// version.
    pub fn credential(&self, label: &[u8], position: u64) -> Result<Option<Credential>> {
        let n = self.served_size()?;
        if position >= n {
            return Err(Error::InvalidArgument("position outside the log"));
        }
        if !Builder::new(self, n, None)?.is_distinguished(position)? {
            return Err(Error::InvalidArgument("position is not distinguished"));
        }
        let mut l = Label::load(self, label, n)?;
        let Some(g) = l.greatest() else {
            return Ok(None);
        };
        let record = l.record(g)?.clone();
        let binary_ladder = search_steps(&mut l, g, g)?;
        let body = if l.greatest_at(position) == Some(g) {
            let mut scratch = Builder::new(self, n, None)?;
            l.ladder(
                &mut scratch,
                position,
                LadderKind::Search { target: g },
                None,
            )?;
            let distinguished = scratch
                .into_proofs()
                .pop()
                .ok_or_else(|| Error::Storage("ladder gave no proof".into()))?;
            CredentialBody::Standard { distinguished }
        } else {
            let mut b = Builder::new(self, n, Some(position + 1))?;
            b.update_view()?;
            greatest_search(&mut b, &mut l, g, self.window())?;
            CredentialBody::Provisional {
                tree_head: self.tree_head()?,
                search: b.finish(&[])?,
            }
        };
        Ok(Some(Credential {
            label: label.to_vec(),
            version: g,
            opening: record.opening,
            value: record.value,
            binary_ladder,
            position,
            body,
        }))
    }

    /// The update for a provisional credential this log issued; `None`
    /// while no distinguished entry lies to the right of its terminal
    /// entry. Its proof is against `q + 1` entries for a user who retained
    /// the credential's tree size `N0` when `N0 <= q + 1`, and for one who
    /// retained nothing otherwise: an entry between the terminal entry and
    /// `N0` can become distinguished as the log grows, and subtrees of
    /// `N0` cannot verify a smaller tree. It starts with the timestamps of
    /// that `update_view`, then §8.2 for `{terminal: version}`.
    pub fn credential_update(&self, credential: &Credential) -> Result<Option<CredentialUpdate>> {
        let CredentialBody::Provisional { tree_head, .. } = &credential.body else {
            return Err(Error::InvalidArgument(
                "only a provisional credential is updated",
            ));
        };
        let n = self.served_size()?;
        let n0 = tree_head.tree_size;
        if n0 == 0 || n0 > n {
            return Err(Error::InvalidArgument("credential head outside the log"));
        }
        let version = credential.version;
        let at_n0 = Label::load(self, &credential.label, n0)?;
        if at_n0.greatest() != Some(version) {
            return Err(Error::InvalidArgument(
                "credential version is not the greatest at its head",
            ));
        }
        let ts = |x: u64| self.store().entry(x).map(|e| e.timestamp);
        let start = match rightmost_distinguished(n0, self.window(), ts)? {
            Some(x) => x,
            None => root(n0)?,
        };
        let terminal = frontier(n0)
            .into_iter()
            .skip_while(|&x| x != start)
            .find(|&x| at_n0.greatest_at(x) == Some(version))
            .ok_or_else(|| Error::Storage("credential version not on the frontier".into()))?;
        let Some(q) = self
            .distinguished_entries()?
            .into_iter()
            .find(|&x| x > terminal)
        else {
            return Ok(None);
        };
        let size = q + 1;
        let retained = (n0 <= size).then_some(n0);
        let mut l = Label::load(self, &credential.label, size)?;
        let mut b = Builder::new(self, size, retained)?;
        b.update_view()?;
        contact(
            &mut b,
            &mut l,
            &[MonitorMapEntry {
                position: terminal,
                version,
            }],
            None,
        )?;
        Ok(Some(CredentialUpdate {
            position: q,
            monitor: b.finish(&[])?,
        }))
    }
}
