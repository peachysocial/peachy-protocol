// SPDX-License-Identifier: MIT
//! The algorithms of draft-ietf-keytrans-protocol-05 that decide which log
//! entries a response covers, written once over an [`Oracle`].
//!
//! A `CombinedTreeProof` (§12.3) says nothing about which entry each
//! timestamp or prefix proof belongs to: they come "in the order that the
//! algorithm the user is executing would request them". So the order is the
//! algorithm, and both sides must run the same one. The verifier runs these
//! walkers over a [`ProofReader`](super::reader::ProofReader), which pops the
//! next timestamp or prefix search result from the response; a prover runs
//! them over a [`ProofRecorder`](super::recorder::ProofRecorder), which
//! answers from the log and writes the response down in the same order.
//!
//! # Readings of the draft
//!
//! Where §12.3 leaves the order open, these walkers (and so every proof this
//! crate makes or accepts) read it as follows:
//!
//! 1. Each entry's timestamp is listed at most once, the first time an
//!    algorithm needs it; the entries on the frontier of the tree size the
//!    user advertised are retained and never listed. Updating the view
//!    (§4.2) always comes first.
//! 2. A prefix proof at an entry is always preceded by a request for that
//!    entry's timestamp (deduplicated like any other): the entry must be a
//!    leaf of the inclusion proof, or retained, for its prefix root to be
//!    bound to the tree.
//! 3. Whether entry `x` is distinguished is found by walking from the root
//!    to `x` with the bounds `(0, ts(n-1))`: at each entry `y`, if `y` is not
//!    distinguished, neither is `x`; if `y == x`, it is; otherwise `y`'s
//!    timestamp is requested and the walk goes on. This is §12.3.4's and
//!    §12.3.7's "the path from the root to the parent, stopping if a
//!    non-distinguished log entry is established".
//! 4. Lookups are omitted (§6.2) in greatest-version search, in fixed-version
//!    search and in steps 2 and 4 of a label update, never in monitoring or
//!    owner ladders. An inclusion is omitted when one was shown for the same
//!    version at an entry to the left, a non-inclusion when one was shown at
//!    an entry to the right, among the entries inspected so far in this
//!    response.
//! 5. A label update (§9.1) skips no entry in step 2: step 2.1 would skip
//!    the entries a previous update inspected, but the log cannot tell
//!    whether the owner learned its greatest version from an update or from
//!    owner initialization, and after initialization the owner knows
//!    neither where that version was inserted nor the versions along that
//!    entry's frontier. Every entry the step reaches gets its ladder, which
//!    only adds checks.

use std::collections::BTreeMap;

use crate::error::Error;
use crate::implicit::{ancestors, frontier, left, right, root, spans_window, update_view};
use crate::ladder::{self, LadderEnd, LadderKind};
use crate::verify::config::Recency;
use crate::verify::error::{VerifyError, VerifyResult};
use crate::wire::MonitorMapEntry;

/// What a walker asks of a response (verifying) or of a log (proving).
pub trait Oracle {
    /// The timestamp of the entry at `position`.
    fn timestamp(&mut self, position: u64) -> VerifyResult<u64>;
    /// Starts the next prefix proof, from the entry at `position`.
    fn begin_proof(&mut self, position: u64) -> VerifyResult<()>;
    /// The next search of the current prefix proof: whether `version` of the
    /// response's label is in the entry's prefix tree.
    fn lookup(&mut self, version: u32) -> VerifyResult<bool>;
    /// Ends the current prefix proof.
    fn end_proof(&mut self) -> VerifyResult<()>;
    /// Draft §8.3, step 4 of owner monitoring, at `position`: `None` to
    /// stop, or the target version of the ladder that follows (`Some(None)`:
    /// the label is expected absent). `expected` is what the label owner's
    /// state expects there. A verifier stops once the response's prefix
    /// proofs are all consumed and otherwise answers `expected`; a prover
    /// answers with the log's own greatest version, or stops.
    fn owner_step(
        &mut self,
        position: u64,
        expected: Option<u32>,
    ) -> VerifyResult<Option<Option<u32>>>;
}

/// Lookups shown so far in one response, for omission (§6.2).
#[derive(Debug, Default, Clone)]
struct Facts {
    /// version → (leftmost entry shown to include it, rightmost entry shown
    /// not to).
    seen: BTreeMap<u32, (Option<u64>, Option<u64>)>,
}

impl Facts {
    fn known(&self, version: u32, position: u64) -> Option<bool> {
        let (incl, excl) = self.seen.get(&version)?;
        if incl.is_some_and(|x| x < position) {
            return Some(true);
        }
        if excl.is_some_and(|x| x > position) {
            return Some(false);
        }
        None
    }

    fn record(&mut self, version: u32, position: u64, included: bool) {
        let entry = self.seen.entry(version).or_insert((None, None));
        if included {
            entry.0 = Some(entry.0.map_or(position, |x| x.min(position)));
        } else {
            entry.1 = Some(entry.1.map_or(position, |x| x.max(position)));
        }
    }
}

/// Runs a ladder against a lookup that can fail with a [`VerifyError`].
fn drive(
    kind: LadderKind,
    mut lookup: impl FnMut(u32) -> VerifyResult<bool>,
) -> VerifyResult<LadderEnd> {
    let mut failure = None;
    let end = ladder::drive(kind, |v| match lookup(v) {
        Ok(b) => Ok(b),
        Err(e) => {
            failure = Some(e);
            Err(Error::InvalidArgument("lookup failed"))
        }
    });
    if let Some(e) = failure {
        return Err(e);
    }
    Ok(end?)
}

/// The versions of a search ladder for `target` when the greatest version
/// is `target` (`None`: the label is absent, target 0): the
/// `binary_ladder` a search response carries (§13.1), and Appendix B's base.
pub fn base_ladder(target: Option<u32>) -> Vec<u32> {
    ladder::versions(
        LadderKind::Search {
            target: target.unwrap_or(0),
        },
        target,
    )
}

/// How a fixed-version search ended (§7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedEnd {
    /// The version exists; its terminal entry.
    Found(u64),
    /// The version does not exist (§7.2 steps 6.1 and 6.3).
    NotFound,
    /// The version has expired (§7.2 steps 5.2 and 6.2).
    Expired,
}

/// The claims of a label update a walker checks (§9.1).
#[derive(Debug, Clone)]
pub struct UpdateClaims<'a> {
    /// The entry the new versions were inserted at.
    pub position: u64,
    /// The greatest version before them.
    pub previous_greatest: Option<u32>,
    /// The new versions, ascending, consecutive after `previous_greatest`.
    pub new_versions: &'a [u32],
}

/// One walk over one response, in a tree of `tree_size` entries.
pub struct Walk<'o, O: Oracle> {
    oracle: &'o mut O,
    n: u64,
    window: u64,
    lifetime: Option<u64>,
    facts: Facts,
}

impl<'o, O: Oracle> Walk<'o, O> {
    /// A walk in a tree of `tree_size` entries with the given monitoring
    /// window and maximum lifetime (milliseconds).
    pub fn new(oracle: &'o mut O, tree_size: u64, window: u64, lifetime: Option<u64>) -> Self {
        Walk {
            oracle,
            n: tree_size,
            window,
            lifetime,
            facts: Facts::default(),
        }
    }

    /// The tree size.
    pub fn tree_size(&self) -> u64 {
        self.n
    }

    fn ts(&mut self, x: u64) -> VerifyResult<u64> {
        if x >= self.n {
            return Err(VerifyError::RequestMismatch("entry outside the tree"));
        }
        self.oracle.timestamp(x)
    }

    fn rightmost(&mut self) -> VerifyResult<u64> {
        let n = self.n;
        if n == 0 {
            return Err(VerifyError::EmptyTree);
        }
        self.ts(n - 1)
    }

    fn root(&self) -> VerifyResult<u64> {
        root(self.n).map_err(|_| VerifyError::EmptyTree)
    }

    fn expired_at(&mut self, ts: u64) -> VerifyResult<bool> {
        match self.lifetime {
            None => Ok(false),
            Some(l) => Ok(self.rightmost()?.saturating_sub(ts) >= l),
        }
    }

    /// §4.2: the timestamps that move a user from `retained` entries to this
    /// tree (all of the frontier when nothing is retained).
    pub fn update_view(&mut self, retained: Option<u64>) -> VerifyResult<()> {
        for x in update_view(self.n, retained)? {
            self.ts(x)?;
        }
        Ok(())
    }

    /// Reading 3 of the module docs.
    pub fn is_distinguished(&mut self, x: u64) -> VerifyResult<bool> {
        if x >= self.n {
            return Err(VerifyError::RequestMismatch("entry outside the tree"));
        }
        let (mut lt, mut rt) = (0, self.rightmost()?);
        let mut y = self.root()?;
        loop {
            if !spans_window(lt, rt, self.window) {
                return Ok(false);
            }
            if y == x {
                return Ok(true);
            }
            let ty = self.ts(y)?;
            if x < y {
                rt = ty;
                y = left(y).ok_or(VerifyError::RequestMismatch("entry outside the tree"))?;
            } else {
                lt = ty;
                y = right(y, self.n)
                    .ok_or(VerifyError::RequestMismatch("entry outside the tree"))?;
            }
        }
    }

    /// One ladder from the entry at `x`, with omission if `omit`.
    pub fn ladder(&mut self, x: u64, kind: LadderKind, omit: bool) -> VerifyResult<LadderEnd> {
        self.ts(x)?;
        self.oracle.begin_proof(x)?;
        let oracle = &mut *self.oracle;
        let facts = &mut self.facts;
        let end = drive(kind, |v| {
            if omit {
                if let Some(known) = facts.known(v, x) {
                    return Ok(known);
                }
            }
            let included = oracle.lookup(v)?;
            if omit {
                facts.record(v, x, included);
            }
            Ok(included)
        })?;
        self.oracle.end_proof()?;
        Ok(end)
    }

    /// One prefix proof from the entry at `x` looking up `versions`, in
    /// order, none omitted.
    pub fn lookups(&mut self, x: u64, versions: &[u32]) -> VerifyResult<Vec<bool>> {
        self.ts(x)?;
        self.oracle.begin_proof(x)?;
        let mut out = Vec::with_capacity(versions.len());
        for &v in versions {
            out.push(self.oracle.lookup(v)?);
        }
        self.oracle.end_proof()?;
        Ok(out)
    }

    /// The rightmost distinguished entry (§6.3), or `None`. It lies on the
    /// frontier, whose timestamps the user holds after updating its view.
    pub fn rightmost_distinguished(&mut self) -> VerifyResult<Option<u64>> {
        let rt = self.rightmost()?;
        let mut lt = 0;
        let mut found = None;
        for x in frontier(self.n) {
            if !spans_window(lt, rt, self.window) {
                break;
            }
            found = Some(x);
            lt = self.ts(x)?;
        }
        Ok(found)
    }

    /// §6.3 greatest-version search for a claimed greatest version `g`;
    /// returns the terminal entry.
    pub fn greatest_search(&mut self, g: u32) -> VerifyResult<u64> {
        let n = self.n;
        let start = match self.rightmost_distinguished()? {
            Some(x) => x,
            None => self.root()?,
        };
        let mut terminal = None;
        for x in frontier(n).into_iter().filter(|&x| x >= start) {
            let end = self.ladder(x, LadderKind::Search { target: g }, true)?;
            if end.above_target {
                return Err(VerifyError::VersionMismatch(
                    "a version above the claimed greatest exists",
                ));
            }
            if x == n - 1 && end.below_target_missing {
                return Err(VerifyError::VersionMismatch(
                    "the claimed greatest version is missing",
                ));
            }
            if terminal.is_none() && !end.below_target_missing {
                terminal = Some(x);
            }
        }
        terminal.ok_or(VerifyError::VersionMismatch(
            "the claimed greatest version is missing",
        ))
    }

    /// §7.2 fixed-version search for version `t`.
    pub fn fixed_search(&mut self, t: u32) -> VerifyResult<FixedEnd> {
        let n = self.n;
        // Inspected entries: position → (expired, the ladder showed a
        // greater version).
        let mut inspected: BTreeMap<u64, (bool, bool)> = BTreeMap::new();
        let mut x = self.root()?;
        let mut equal_at = None;
        loop {
            let tx = self.ts(x)?;
            let expired = self.expired_at(tx)?;
            let next = if expired {
                inspected.insert(x, (true, false));
                right(x, n)
            } else {
                let end = self.ladder(x, LadderKind::Search { target: t }, true)?;
                if end.below_target_missing {
                    inspected.insert(x, (false, false));
                    right(x, n)
                } else if end.above_target {
                    inspected.insert(x, (false, true));
                    left(x)
                } else {
                    inspected.insert(x, (false, false));
                    equal_at = Some(x);
                    None
                }
            };
            match next {
                Some(y) => x = y,
                None => break,
            }
        }
        let any_expired = inspected.values().any(|(e, _)| *e);
        if let Some(x) = equal_at {
            // Step 5.
            let path_expired = ancestors(x, n)?
                .iter()
                .any(|a| inspected.get(a).is_some_and(|(e, _)| *e));
            if !path_expired {
                return Ok(FixedEnd::Found(x));
            }
            if self.is_distinguished(x)? {
                return Ok(FixedEnd::Found(x));
            }
            for a in ancestors(x, n)?.into_iter().filter(|&a| a < x) {
                let expired = inspected.get(&a).is_some_and(|(e, _)| *e);
                if !expired && self.is_distinguished(a)? {
                    return Ok(FixedEnd::Found(x));
                }
            }
            return Ok(FixedEnd::Expired);
        }
        // Step 6.
        let Some(identified) = inspected
            .iter()
            .find(|(_, (_, greater))| *greater)
            .map(|(p, _)| *p)
        else {
            return Ok(FixedEnd::NotFound);
        };
        if any_expired {
            let mut anchored = false;
            let left_of: Vec<(u64, bool)> = inspected
                .range(..identified)
                .map(|(p, (e, _))| (*p, *e))
                .collect();
            for (p, expired) in left_of {
                if !expired && self.is_distinguished(p)? {
                    anchored = true;
                    break;
                }
            }
            if !anchored {
                return Ok(FixedEnd::Expired);
            }
        }
        let found = self.lookups(identified, &[t])?;
        Ok(if found.first().copied().unwrap_or(false) {
            FixedEnd::Found(identified)
        } else {
            FixedEnd::NotFound
        })
    }

    /// §8.2 contact monitoring of `map` (ascending by position), in the
    /// context of owner monitoring when `owner_start` is given. Returns the
    /// new map, ascending.
    pub fn contact_monitor(
        &mut self,
        map: &[MonitorMapEntry],
        owner_start: Option<u64>,
    ) -> VerifyResult<Vec<MonitorMapEntry>> {
        let n = self.n;
        let mut provided: BTreeMap<u64, u32> = BTreeMap::new();
        let mut out: Vec<MonitorMapEntry> = Vec::new();
        for entry in map.iter().rev() {
            let (p, v) = (entry.position, entry.version);
            if p >= n {
                return Err(VerifyError::RequestMismatch(
                    "monitored entry outside the tree",
                ));
            }
            if self.is_distinguished(p)? {
                out.push(*entry);
                continue;
            }
            let mut list: Vec<u64> = ancestors(p, n)?.into_iter().filter(|&a| a > p).collect();
            let mut final_distinguished = false;
            for i in 0..list.len() {
                if self.is_distinguished(list[i])? {
                    list.truncate(i + 1);
                    final_distinguished = true;
                    break;
                }
            }
            if final_distinguished && owner_start.is_some_and(|s| p >= s) {
                list.pop();
            }
            let mut current = Some(*entry);
            for a in list {
                if let Some(&previous) = provided.get(&a) {
                    if previous > v {
                        current = None;
                        break;
                    }
                    return Err(VerifyError::VersionMismatch(
                        "a monitored version meets an equal or greater one",
                    ));
                }
                let end = self.ladder(a, LadderKind::Monitor { target: v }, false)?;
                if end.below_target_missing {
                    return Err(VerifyError::VersionMismatch(
                        "a monitored version is missing",
                    ));
                }
                provided.insert(a, v);
                current = Some(MonitorMapEntry {
                    position: a,
                    version: v,
                });
            }
            if let Some(e) = current {
                out.push(e);
            }
        }
        let mut kept = Vec::with_capacity(out.len());
        for e in out {
            if !self.is_distinguished(e.position)? {
                kept.push(e);
            }
        }
        kept.sort_by_key(|e| e.position);
        Ok(kept)
    }

    /// The first algorithm of §8.3 from the distinguished entry `start`,
    /// with `greatest` the claimed greatest versions along its list. Returns
    /// the list (start, then its left ancestors, nearest first, up to the
    /// first expired).
    pub fn owner_init(&mut self, start: u64, greatest: &[u32]) -> VerifyResult<Vec<u64>> {
        let n = self.n;
        if start >= n {
            return Err(VerifyError::RequestMismatch("start outside the tree"));
        }
        let mut path = ancestors(start, n)?;
        path.reverse();
        path.push(start);
        for &y in &path {
            self.ts(y)?;
        }
        let ts_start = self.ts(start)?;
        if !self.is_distinguished(start)? || self.expired_at(ts_start)? {
            return Err(VerifyError::RequestMismatch(
                "start is not an unexpired distinguished entry",
            ));
        }
        let mut list = vec![start];
        for a in ancestors(start, n)?.into_iter().filter(|&a| a < start) {
            let ta = self.ts(a)?;
            if self.expired_at(ta)? {
                break;
            }
            list.push(a);
        }
        if greatest.len() > list.len() {
            return Err(VerifyError::Proof("more greatest versions than entries"));
        }
        for (i, &x) in list.iter().enumerate() {
            let claimed = greatest.get(i).copied();
            let end = self.ladder(
                x,
                LadderKind::Search {
                    target: claimed.unwrap_or(0),
                },
                false,
            )?;
            if end.exact_greatest() != Some(claimed) {
                return Err(VerifyError::VersionMismatch(
                    "a ladder contradicts the claimed greatest version",
                ));
            }
        }
        Ok(list)
    }

    /// The second algorithm of §8.3, after the owner's verified entry
    /// `start`, with `expected` giving the version the owner expects to be
    /// greatest at an entry. Returns every entry a ladder verified, in order.
    pub fn owner_monitor(
        &mut self,
        start: u64,
        expected: &dyn Fn(u64) -> Option<u32>,
    ) -> VerifyResult<Vec<u64>> {
        let rt = self.rightmost()?;
        let r = self.root()?;
        let mut verified = Vec::new();
        let mut stopped = false;
        self.owner_rec(r, 0, rt, start, expected, &mut verified, &mut stopped)?;
        Ok(verified)
    }

    #[allow(clippy::too_many_arguments)]
    fn owner_rec(
        &mut self,
        x: u64,
        lt: u64,
        rt: u64,
        start: u64,
        expected: &dyn Fn(u64) -> Option<u32>,
        verified: &mut Vec<u64>,
        stopped: &mut bool,
    ) -> VerifyResult<()> {
        let n = self.n;
        if *stopped || !spans_window(lt, rt, self.window) {
            return Ok(());
        }
        if x <= start {
            if let Some(r) = right(x, n) {
                let tx = self.ts(x)?;
                self.owner_rec(r, tx, rt, start, expected, verified, stopped)?;
            }
            return Ok(());
        }
        if let Some(l) = left(x) {
            let tx = self.ts(x)?;
            self.owner_rec(l, lt, tx, start, expected, verified, stopped)?;
        }
        if *stopped {
            return Ok(());
        }
        let Some(target) = self.oracle.owner_step(x, expected(x))? else {
            *stopped = true;
            return Ok(());
        };
        let end = self.ladder(
            x,
            LadderKind::Search {
                target: target.unwrap_or(0),
            },
            false,
        )?;
        if end.exact_greatest() != Some(target) {
            return Err(VerifyError::VersionMismatch(
                "a distinguished entry holds a version the owner did not expect",
            ));
        }
        verified.push(x);
        if let Some(r) = right(x, n) {
            let tx = self.ts(x)?;
            self.owner_rec(r, tx, rt, start, expected, verified, stopped)?;
        }
        Ok(())
    }

    /// §9.1, checking a label update's claims. Returns whether the
    /// insertion entry is distinguished in this tree.
    pub fn update(&mut self, claims: &UpdateClaims<'_>) -> VerifyResult<bool> {
        let n = self.n;
        let p = claims.position;
        if p == 0 || p >= n {
            return Err(VerifyError::Proof("update position outside the tree"));
        }
        let g_new = *claims
            .new_versions
            .last()
            .ok_or(VerifyError::Proof("an update with no new version"))?;
        // The timestamps on the paths to P-1 and to P (§12.3.7).
        self.is_distinguished(p - 1)?;
        let p_distinguished = self.is_distinguished(p)?;
        let previous_frontier = frontier(p);
        let mut first = None;
        for (i, &f) in previous_frontier.iter().enumerate() {
            if !self.is_distinguished(f)? {
                first = Some(i);
                break;
            }
        }
        let target = claims.previous_greatest.unwrap_or(0);
        if let Some(i) = first {
            // Reading 5: step 2.1's skip is not applied. Step 2.3 is a
            // greatest-version search's test: no version above the previous
            // greatest (none at all when there was none). An entry left of
            // where that version was inserted rightly shows it absent.
            for &f in &previous_frontier[i..] {
                let end = self.ladder(f, LadderKind::Search { target }, true)?;
                let above = match claims.previous_greatest {
                    Some(_) => end.above_target,
                    None => end.greatest_included.is_some() || end.above_target,
                };
                if above {
                    return Err(VerifyError::VersionMismatch(
                        "the previous tree holds a version the owner did not expect",
                    ));
                }
            }
        }
        let base_new = base_ladder(Some(g_new));
        let extra: Vec<u32> = claims
            .new_versions
            .iter()
            .copied()
            .filter(|v| !base_new.contains(v))
            .collect();
        if !p_distinguished {
            let end = self.ladder(p, LadderKind::Search { target: g_new }, true)?;
            if end.exact_greatest() != Some(Some(g_new)) {
                return Err(VerifyError::VersionMismatch(
                    "the insertion entry does not hold the new greatest version",
                ));
            }
        }
        if !extra.is_empty() && self.lookups(p, &extra)?.iter().any(|b| !b) {
            return Err(VerifyError::VersionMismatch(
                "a new version is missing from its insertion entry",
            ));
        }
        Ok(p_distinguished)
    }

    /// §10.1 walking the recent distinguished entries, stopping at `stop`.
    /// Returns the recent entries found, right to left.
    pub fn distinguished(&mut self, stop: Option<u64>, recency: Recency) -> VerifyResult<Vec<u64>> {
        let rt = self.rightmost()?;
        let r = self.root()?;
        let mut found = Vec::new();
        self.dist_rec(r, 0, rt, stop, recency, &mut found)?;
        Ok(found)
    }

    fn dist_rec(
        &mut self,
        x: u64,
        lt: u64,
        rt: u64,
        stop: Option<u64>,
        recency: Recency,
        found: &mut Vec<u64>,
    ) -> VerifyResult<()> {
        if !spans_window(lt, rt, self.window) {
            return Ok(());
        }
        let tx = self.ts(x)?;
        if let Some(r) = right(x, self.n) {
            self.dist_rec(r, tx, rt, stop, recency, found)?;
        }
        if stop.is_some_and(|s| x <= s) {
            return Ok(());
        }
        let recent = match recency {
            Recency::Window(w) => self.rightmost()?.saturating_sub(tx) < w,
            Recency::Count(c) => (found.len() as u64) < u64::from(c),
        };
        if !recent {
            return Ok(());
        }
        found.push(x);
        if let Some(l) = left(x) {
            self.dist_rec(l, lt, tx, stop, recency, found)?;
        }
        Ok(())
    }
}
