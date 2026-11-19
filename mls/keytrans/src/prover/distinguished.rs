// SPDX-License-Identifier: MIT
//! Walking distinguished heads (§10, §13.6).
//!
//! The walk is §10.1's right-to-left depth-first search from the root. The
//! order a verifier asks in, after the update view: the timestamp of each
//! entry that reaches step 2, that is, each distinguished entry the walk
//! visits, when it visits it. No prefix proofs, so every listed entry's
//! prefix root is in `prefix_roots`.

use super::proof::{root_of, Builder};
use super::storage::Storage;
use super::Prover;
use crate::error::Result;
use crate::implicit::{left, right, spans_window};
use crate::wire::{DistinguishedRequest, DistinguishedResponse};

/// The application's definition of a "recent" distinguished entry (§10.1);
/// both of the draft's recommended ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recent {
    /// Its timestamp is less than this many milliseconds before the
    /// rightmost entry's.
    Within(u64),
    /// It is one of this many rightmost distinguished entries.
    Rightmost(u64),
}

struct Walk {
    n: u64,
    window: u64,
    stop: Option<u64>,
    recent: Recent,
    rightmost: u64,
    /// Distinguished entries visited so far, by position.
    seen: Vec<u64>,
}

impl Walk {
    fn visit<S: Storage>(
        &mut self,
        b: &mut Builder<'_, S>,
        x: u64,
        lt: u64,
        rt: u64,
    ) -> Result<()> {
        // Step 1.
        if !spans_window(lt, rt, self.window) {
            return Ok(());
        }
        let tx = b.timestamp(x)?;
        self.seen.push(x);
        // Step 2.
        if let Some(r) = right(x, self.n) {
            self.visit(b, r, tx, rt)?;
        }
        // Step 3.
        if self.stop.is_some_and(|s| x <= s) {
            return Ok(());
        }
        // Step 4.
        let recent = match self.recent {
            Recent::Within(ms) => self.rightmost.saturating_sub(tx) < ms,
            Recent::Rightmost(count) => {
                (self.seen.iter().filter(|&&y| y > x).count() as u64) < count
            }
        };
        if !recent {
            return Ok(());
        }
        // Step 5.
        if let Some(l) = left(x) {
            self.visit(b, l, lt, tx)?;
        }
        Ok(())
    }
}

impl<S: Storage> Prover<S> {
    /// Answers a request to walk the recent distinguished entries (§13.6),
    /// `recent` being the application's definition.
    pub fn distinguished(
        &self,
        request: &DistinguishedRequest,
        recent: Recent,
    ) -> Result<DistinguishedResponse> {
        let n = self.served_size()?;
        let (full_tree_head, extra) = self.full_tree_head(n, request.last)?;
        let mut b = Builder::new(self, n, request.last)?;
        b.update_view()?;
        let rightmost = b.peek(n - 1)?;
        let mut walk = Walk {
            n,
            window: self.window(),
            stop: request.stop,
            recent,
            rightmost,
            seen: Vec::new(),
        };
        walk.visit(&mut b, root_of(n)?, 0, rightmost)?;
        Ok(DistinguishedResponse {
            full_tree_head,
            distinguished: b.finish(&extra)?,
        })
    }
}
