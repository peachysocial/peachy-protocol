// SPDX-License-Identifier: MIT
//! Monitoring (§8, §13.2 to §13.4): contact monitoring, and the owner's
//! two algorithms.
//!
//! The order a verifier asks in, after the update view:
//!
//! - **Contact monitoring** (§8.2, §12.3.4): map entries from rightmost to
//!   leftmost. For each, the distinguished walk to the entry (rule 3 of
//!   [`crate::prover`]); if the entry is distinguished, nothing more. Else
//!   its list: its ancestors to its right, nearest first, cut just after the
//!   first distinguished one (and, under owner monitoring, that one dropped
//!   when the entry is at or after the owner's start). One monitoring
//!   ladder per list entry, target the map entry's version, until an entry
//!   already given a ladder in this response for a greater version, where
//!   the map entry is done. Monitoring ladders omit nothing.
//! - **Owner initialization** (§8.3 first algorithm, §12.3.5): the
//!   timestamp of each entry on the path from the root to the start,
//!   root first, then one search ladder per entry of the list (the start,
//!   then its ancestors to its left, nearest first), target the label's
//!   greatest version there or 0 where it has none, omitting nothing.
//! - **Owner monitoring** (§13.4, §12.3.6): contact monitoring of the
//!   request's map with the owner's start, then the second algorithm of
//!   §8.3 from the root: an entry's timestamp is asked for when the walk
//!   recurses from it (step 2.1, step 3, step 6), and an entry that reaches
//!   step 5 gets a search ladder with target its greatest version (0 if
//!   none), omitting nothing. The log stops the whole walk at step 4 when
//!   the greatest version there exceeds the one the owner advertised, or
//!   after `max_ladders` ladders.

use std::collections::{BTreeMap, BTreeSet};

use super::proof::{base_ladder, root_of, Builder, Label};
use super::storage::Storage;
use super::Prover;
use crate::error::{Error, Result};
use crate::implicit::{ancestors, left, right, spans_window};
use crate::ladder::LadderKind;
use crate::wire::{
    ContactMonitorRequest, ContactMonitorResponse, MonitorMapEntry, OwnerInitRequest,
    OwnerInitResponse, OwnerMonitorRequest, OwnerMonitorResponse,
};

/// The request checks of §13.2 and §13.4 step 1: ascending positions, no
/// position or version twice, each version existing and each position on
/// the direct path of the entry that added the version, at or to its right.
fn check_entries<S: Storage>(
    label: &Label<'_, S>,
    entries: &[MonitorMapEntry],
    n: u64,
) -> Result<()> {
    if entries.len() > 0xff {
        return Err(Error::InvalidArgument("too many monitoring map entries"));
    }
    if entries
        .windows(2)
        .any(|w| matches!(w, [a, b] if a.position >= b.position))
    {
        return Err(Error::InvalidArgument("monitoring map out of order"));
    }
    let mut seen = BTreeSet::new();
    for e in entries {
        if !seen.insert(e.version) {
            return Err(Error::InvalidArgument("a version monitored twice"));
        }
        let first = label
            .record(e.version)
            .map_err(|_| Error::InvalidArgument("monitoring a version that does not exist"))?
            .position;
        if e.position >= n
            || e.position < first
            || !(e.position == first || ancestors(first, n)?.contains(&e.position))
        {
            return Err(Error::InvalidArgument(
                "monitored position off the version's direct path",
            ));
        }
    }
    Ok(())
}

/// §8.2 over `entries`; `owner_start` when run inside owner monitoring.
pub(crate) fn contact<S: Storage>(
    b: &mut Builder<'_, S>,
    label: &mut Label<'_, S>,
    entries: &[MonitorMapEntry],
    owner_start: Option<u64>,
) -> Result<()> {
    let n = b.n();
    let mut laddered: BTreeMap<u64, u32> = BTreeMap::new();
    for e in entries.iter().rev() {
        let p = e.position;
        if b.is_distinguished(p)? {
            continue;
        }
        let mut list = Vec::new();
        let mut ends_distinguished = false;
        for a in ancestors(p, n)? {
            if a < p {
                continue;
            }
            list.push(a);
            if b.is_distinguished(a)? {
                ends_distinguished = true;
                break;
            }
        }
        if ends_distinguished && owner_start.is_some_and(|s| p >= s) {
            list.pop();
        }
        for y in list {
            if let Some(&t) = laddered.get(&y) {
                if t > e.version {
                    break;
                }
                return Err(Error::InvalidArgument(
                    "monitoring map would fail: an entry already monitored at a version not above this one",
                ));
            }
            label.ladder(b, y, LadderKind::Monitor { target: e.version }, None)?;
            laddered.insert(y, e.version);
        }
    }
    Ok(())
}

impl<S: Storage> Prover<S> {
    /// Answers a contact monitoring request (§13.2).
    pub fn contact_monitor(
        &self,
        request: &ContactMonitorRequest,
    ) -> Result<ContactMonitorResponse> {
        let n = self.served_size()?;
        let (full_tree_head, extra) = self.full_tree_head(n, request.last)?;
        let mut label = Label::load(self, &request.label, n)?;
        check_entries(&label, &request.entries, n)?;
        let mut b = Builder::new(self, n, request.last)?;
        b.update_view()?;
        contact(&mut b, &mut label, &request.entries, None)?;
        Ok(ContactMonitorResponse {
            full_tree_head,
            monitor: b.finish(&extra)?,
        })
    }

    /// Answers an owner initialization request (§13.3). The start must be a
    /// distinguished entry.
    pub fn owner_init(&self, request: &OwnerInitRequest) -> Result<OwnerInitResponse> {
        let n = self.served_size()?;
        let start = request.start;
        if start >= n {
            return Err(Error::InvalidArgument("start outside the log"));
        }
        if !Builder::new(self, n, None)?.is_distinguished(start)? {
            return Err(Error::InvalidArgument("start is not distinguished"));
        }
        let (full_tree_head, extra) = self.full_tree_head(n, request.last)?;
        let mut label = Label::load(self, &request.label, n)?;
        let mut b = Builder::new(self, n, request.last)?;
        b.update_view()?;

        let up = ancestors(start, n)?;
        for &y in up.iter().rev() {
            b.timestamp(y)?;
        }
        b.timestamp(start)?;

        let list: Vec<u64> = std::iter::once(start)
            .chain(up.into_iter().filter(|&a| a < start))
            .collect();
        let mut greatest_versions = Vec::new();
        for &x in &list {
            match label.greatest_at(x) {
                Some(g) => greatest_versions.push(g),
                None => break,
            }
        }
        for &x in &list {
            let target = label.greatest_at(x).unwrap_or(0);
            label.ladder(&mut b, x, LadderKind::Search { target }, None)?;
        }

        let mut versions: BTreeSet<u32> = BTreeSet::from([0]);
        for &g in &greatest_versions {
            versions.extend(base_ladder(g));
        }
        let versions: Vec<u32> = versions.into_iter().collect();
        let known = greatest_versions.first().copied();
        let binary_ladder = label.steps(&versions, |v| known.is_some_and(|g| v <= g))?;
        Ok(OwnerInitResponse {
            full_tree_head,
            greatest_versions,
            binary_ladder,
            init: b.finish(&extra)?,
        })
    }

    /// Answers an owner monitoring request (§13.4), giving at most
    /// `max_ladders` ladders in the §8.3 walk (the owner asks again for
    /// the rest).
    pub fn owner_monitor(
        &self,
        request: &OwnerMonitorRequest,
        max_ladders: usize,
    ) -> Result<OwnerMonitorResponse> {
        let n = self.served_size()?;
        let (full_tree_head, extra) = self.full_tree_head(n, request.last)?;
        let mut label = Label::load(self, &request.label, n)?;
        check_entries(&label, &request.entries, n)?;
        if request.start >= n {
            return Err(Error::InvalidArgument("start outside the log"));
        }
        match (request.greatest_version, label.greatest()) {
            (Some(v), Some(g)) if v > g => {
                return Err(Error::InvalidArgument("advertised version does not exist"))
            }
            (Some(_), None) => {
                return Err(Error::InvalidArgument("advertised version does not exist"))
            }
            _ => {}
        }
        if let Some(at_start) = label.greatest_at(request.start) {
            if request.greatest_version.is_none_or(|v| v < at_start) {
                return Err(Error::InvalidArgument(
                    "advertised version below the one at the start",
                ));
            }
        }

        let mut b = Builder::new(self, n, request.last)?;
        b.update_view()?;
        contact(&mut b, &mut label, &request.entries, Some(request.start))?;

        let rt = b.peek(n - 1)?;
        let mut walk = OwnerWalk {
            n,
            window: self.window(),
            start: request.start,
            advertised: request.greatest_version,
            max_ladders,
            ladders: 0,
        };
        walk.visit(&mut b, &mut label, root_of(n)?, 0, rt)?;
        Ok(OwnerMonitorResponse {
            full_tree_head,
            monitor: b.finish(&extra)?,
        })
    }
}

/// Whether the §8.3 walk goes on.
#[derive(PartialEq, Eq)]
enum Flow {
    Go,
    Stop,
}

struct OwnerWalk {
    n: u64,
    window: u64,
    start: u64,
    advertised: Option<u32>,
    max_ladders: usize,
    ladders: usize,
}

impl OwnerWalk {
    fn visit<S: Storage>(
        &mut self,
        b: &mut Builder<'_, S>,
        label: &mut Label<'_, S>,
        x: u64,
        lt: u64,
        rt: u64,
    ) -> Result<Flow> {
        // Step 1.
        if !spans_window(lt, rt, self.window) {
            return Ok(Flow::Go);
        }
        // Step 2.
        if x <= self.start {
            if let Some(r) = right(x, self.n) {
                let t = b.timestamp(x)?;
                return self.visit(b, label, r, t, rt);
            }
            return Ok(Flow::Go);
        }
        // Step 3.
        if let Some(l) = left(x) {
            let t = b.timestamp(x)?;
            if self.visit(b, label, l, lt, t)? == Flow::Stop {
                return Ok(Flow::Stop);
            }
        }
        // Step 4.
        let g = label.greatest_at(x);
        let beyond = match (g, self.advertised) {
            (Some(g), Some(a)) => g > a,
            (Some(_), None) => true,
            (None, _) => false,
        };
        if beyond || self.ladders >= self.max_ladders {
            return Ok(Flow::Stop);
        }
        // Step 5.
        label.ladder(
            b,
            x,
            LadderKind::Search {
                target: g.unwrap_or(0),
            },
            None,
        )?;
        self.ladders += 1;
        // Step 6.
        if let Some(r) = right(x, self.n) {
            let t = b.timestamp(x)?;
            return self.visit(b, label, r, t, rt);
        }
        Ok(Flow::Go)
    }
}
