// SPDX-License-Identifier: MIT
//! Search (§6, §7, §13.1).
//!
//! The order a verifier asks in, after the update view:
//!
//! - **Greatest version `g`** (§6.3, §12.3.2): from the rightmost
//!   distinguished entry (the root if there is none) down the rest of the
//!   frontier, one search ladder per entry with target `g`, omitting
//!   inclusions shown to the left. Every frontier timestamp is already in
//!   the update view or retained, so the search adds none.
//! - **Fixed version `t`** (§7.2, §12.3.3): the binary search from the root,
//!   one search ladder per entry touched with target `t`, omitting
//!   inclusions shown to the left and non-inclusions shown to the right. If
//!   it ends without an entry where `t` is the greatest (step 6), one more
//!   prefix proof, for `t` alone, at the leftmost entry whose ladder showed
//!   a greater version.
//!
//! `binary_ladder` is Appendix B's `base_binary_ladder` of the target, with
//! the commitment of every version that exists except the target's.

use super::proof::{base_ladder, root_of, Builder, Label, Omission};
use super::storage::Storage;
use super::Prover;
use crate::error::{Error, Result};
use crate::implicit::{frontier, left, right, rightmost_distinguished};
use crate::ladder::LadderKind;
use crate::wire::{BinaryLadderStep, SearchRequest, SearchResponse};

/// The greatest-version search's ladders for greatest version `g`; returns
/// the terminal entry (the leftmost inspected that holds `g`).
pub(crate) fn greatest_search<S: Storage>(
    b: &mut Builder<'_, S>,
    label: &mut Label<'_, S>,
    g: u32,
    window: u64,
) -> Result<u64> {
    let n = b.n();
    let start = match rightmost_distinguished(n, window, |x| b.peek(x))? {
        Some(x) => x,
        None => root_of(n)?,
    };
    let mut omit = Omission::left_inclusions();
    let mut terminal = None;
    for x in frontier(n).into_iter().skip_while(|&x| x != start) {
        label.ladder(b, x, LadderKind::Search { target: g }, Some(&mut omit))?;
        if terminal.is_none() && label.greatest_at(x) == Some(g) {
            terminal = Some(x);
        }
    }
    terminal.ok_or_else(|| Error::Storage("greatest version not on the frontier".into()))
}

/// The ladder steps for a search with `target`, where `greatest` is the
/// label's greatest version.
pub(crate) fn search_steps<S: Storage>(
    label: &mut Label<'_, S>,
    target: u32,
    greatest: u32,
) -> Result<Vec<BinaryLadderStep>> {
    label.steps(&base_ladder(target), |v| v != target && v <= greatest)
}

impl<S: Storage> Prover<S> {
    /// Answers a search: the greatest version when `request.version` is
    /// absent, else that version. `None` when the label, or that version of
    /// it, does not exist.
    pub fn search(&self, request: &SearchRequest) -> Result<Option<SearchResponse>> {
        let n = self.served_size()?;
        let (full_tree_head, extra) = self.full_tree_head(n, request.last)?;
        let mut label = Label::load(self, &request.label, n)?;
        let Some(g) = label.greatest() else {
            return Ok(None);
        };
        let target = match request.version {
            Some(t) if t > g => return Ok(None),
            Some(t) => t,
            None => g,
        };
        let mut b = Builder::new(self, n, request.last)?;
        b.update_view()?;
        if request.version.is_none() {
            greatest_search(&mut b, &mut label, g, self.window())?;
        } else {
            fixed_search(&mut b, &mut label, target)?;
        }
        let record = label.record(target)?.clone();
        let binary_ladder = search_steps(&mut label, target, g)?;
        Ok(Some(SearchResponse {
            full_tree_head,
            version: request.version.is_none().then_some(g),
            opening: record.opening,
            value: record.value,
            binary_ladder,
            search: b.finish(&extra)?,
        }))
    }
}

/// The fixed-version search's ladders for `t` (which exists).
fn fixed_search<S: Storage>(
    b: &mut Builder<'_, S>,
    label: &mut Label<'_, S>,
    t: u32,
) -> Result<()> {
    let n = b.n();
    let mut omit = Omission::both();
    let mut x = root_of(n)?;
    let mut leftmost_greater: Option<u64> = None;
    loop {
        let end = label.ladder(b, x, LadderKind::Search { target: t }, Some(&mut omit))?;
        let next = if end.below_target_missing {
            right(x, n)
        } else if end.above_target {
            leftmost_greater = Some(leftmost_greater.map_or(x, |y| y.min(x)));
            left(x)
        } else {
            // Step 5: t is the greatest version here.
            return Ok(());
        };
        match next {
            Some(y) => x = y,
            None => break,
        }
    }
    // Step 6.
    let at =
        leftmost_greater.ok_or_else(|| Error::Storage("version not found by search".into()))?;
    let key = label.output(t)?;
    b.prefix(at, &[key])
}
