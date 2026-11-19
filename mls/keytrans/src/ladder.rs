// SPDX-License-Identifier: MIT
//! Binary ladders (draft-ietf-keytrans-protocol-05 §5, §6.2, §8.1,
//! Appendix B): the series of version lookups in one log entry's prefix tree
//! that bounds a label's greatest version there.
//!
//! The series is not fixed in advance: each lookup's outcome picks the next
//! version. [`drive`] runs it against a `lookup` callback, so the prover and
//! the verifier share one definition:
//!
//! - the prover answers each lookup from its tree and records it as a
//!   [`BinaryLadderStep`](crate::wire::BinaryLadderStep) and a prefix search;
//! - the verifier answers from the response, popping the next search result,
//!   or from what it already knows when the context lets the log omit a
//!   lookup (§6.2: an inclusion already shown in an entry to the left, a
//!   non-inclusion already shown in an entry to the right).
//!
//! Versions are `u32` on the wire. The doubling phase can name versions past
//! `u32::MAX`; those cannot exist, so they count as non-inclusions and are
//! never passed to `lookup`.

use crate::error::Result;

/// Which ladder to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LadderKind {
    /// The full series of §5: it determines the greatest version exactly.
    Greatest,
    /// A search ladder (§6.2) for `target`: it stops after the first
    /// inclusion of a version above the target or the first non-inclusion
    /// of a version at or below it.
    Search {
        /// The version searched for.
        target: u32,
    },
    /// A monitoring ladder (§8.1) for `target`: the series for a greatest
    /// version of `target`, without the lookups above it. Every lookup must
    /// be an inclusion if the log is honest.
    Monitor {
        /// The version monitored.
        target: u32,
    },
}

/// What a ladder established about the greatest version in its entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LadderEnd {
    /// The greatest version shown (or known) to be included, if any.
    pub greatest_included: Option<u32>,
    /// The least version shown (or assumed) not to be included, if any;
    /// may exceed `u32::MAX`.
    pub least_excluded: Option<u64>,
    /// Whether some version above the target was included (search ladders).
    pub above_target: bool,
    /// Whether some version at or below the target was not included
    /// (search and monitoring ladders).
    pub below_target_missing: bool,
}

impl LadderEnd {
    /// The greatest version exactly, when the ladder pinned it down: the
    /// least exclusion sits right above the greatest inclusion.
    pub fn exact_greatest(&self) -> Option<Option<u32>> {
        match (self.greatest_included, self.least_excluded) {
            (None, Some(0)) => Some(None),
            (Some(g), Some(e)) if u64::from(g) + 1 == e => Some(Some(g)),
            _ => None,
        }
    }
}

/// Runs a ladder. `lookup(v)` returns whether version `v` is included in the
/// entry's prefix tree; it is called in the order the ladder's searches are
/// listed (before any omission the caller applies).
pub fn drive(kind: LadderKind, mut lookup: impl FnMut(u32) -> Result<bool>) -> Result<LadderEnd> {
    let target = match kind {
        LadderKind::Greatest => None,
        LadderKind::Search { target } | LadderKind::Monitor { target } => Some(u64::from(target)),
    };
    let mut end = LadderEnd {
        greatest_included: None,
        least_excluded: None,
        above_target: false,
        below_target_missing: false,
    };
    // Greatest version known included, and least known excluded, as u64.
    let mut lower: Option<u64> = None;
    let mut upper: Option<u64> = None;
    let mut doubling_step: u32 = 0;

    loop {
        let v: u64 = match upper {
            // Doubling: 0, 1, 3, 7, ... until the first non-inclusion.
            None => (1u64 << doubling_step) - 1,
            // Bisection between the bounds.
            Some(hi) => {
                let lo = match lower {
                    Some(lo) => lo,
                    None => break, // version 0 was excluded
                };
                if lo + 1 >= hi {
                    break;
                }
                lo + (hi - lo) / 2
            }
        };

        let included = match (kind, u32::try_from(v)) {
            (_, Err(_)) => false,
            (LadderKind::Monitor { target }, Ok(version)) if version > target => false,
            (_, Ok(version)) => lookup(version)?,
        };

        if included {
            lower = Some(v);
        } else {
            upper = Some(v);
        }
        if upper.is_none() {
            doubling_step += 1;
            if doubling_step > 33 {
                // Unreachable: 2^33 - 1 exceeds u32::MAX and counts as excluded.
                break;
            }
        }

        if let Some(t) = target {
            if included && v > t {
                end.above_target = true;
            }
            if !included && v <= t {
                end.below_target_missing = true;
            }
            if matches!(kind, LadderKind::Search { .. })
                && (end.above_target || end.below_target_missing)
            {
                break;
            }
        }
    }

    end.greatest_included = lower.and_then(|l| u32::try_from(l).ok());
    end.least_excluded = upper;
    Ok(end)
}

/// The versions a ladder looks up when the label's greatest version in the
/// entry is `greatest` (`None`: the label has no version there), in order.
/// Appendix B's functions, before any omission.
pub fn versions(kind: LadderKind, greatest: Option<u32>) -> Vec<u32> {
    let mut out = Vec::new();
    let _ = drive(kind, |v| {
        out.push(v);
        Ok(greatest.is_some_and(|g| v <= g))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    fn search(t: u32, n: Option<u32>) -> Vec<u32> {
        versions(LadderKind::Search { target: t }, n)
    }

    #[test]
    fn section_5_example() {
        // Greatest version 6: inclusions 0, 1, 3; non-inclusion 7; then 5, 6.
        assert_eq!(
            versions(LadderKind::Greatest, Some(6)),
            vec![0, 1, 3, 7, 5, 6]
        );
        let end = drive(LadderKind::Greatest, |v| Ok(v <= 6)).unwrap();
        assert_eq!(end.exact_greatest(), Some(Some(6)));
    }

    #[test]
    fn base_ladders() {
        assert_eq!(versions(LadderKind::Greatest, None), vec![0]);
        assert_eq!(versions(LadderKind::Greatest, Some(0)), vec![0, 1]);
        assert_eq!(versions(LadderKind::Greatest, Some(1)), vec![0, 1, 3, 2]);
        assert_eq!(
            versions(LadderKind::Greatest, Some(7)),
            vec![0, 1, 3, 7, 15, 11, 9, 8]
        );
        assert_eq!(
            versions(LadderKind::Greatest, Some(8)),
            vec![0, 1, 3, 7, 15, 11, 9, 8]
        );
        // The greatest possible version: doubling and bisection past u32::MAX
        // never reach `lookup`.
        let v = versions(LadderKind::Greatest, Some(u32::MAX));
        assert_eq!(v.len(), 33);
        assert_eq!(*v.last().unwrap(), u32::MAX);
        let end = drive(LadderKind::Greatest, |_| Ok(true)).unwrap();
        assert_eq!(end.exact_greatest(), Some(Some(u32::MAX)));
        for n in 0..2000u32 {
            let end = drive(LadderKind::Greatest, |v| Ok(v <= n)).unwrap();
            assert_eq!(end.exact_greatest(), Some(Some(n)), "n={n}");
        }
        let end = drive(LadderKind::Greatest, |_| Ok(false)).unwrap();
        assert_eq!(end.exact_greatest(), Some(None));
    }

    /// Appendix B's search ladder, transcribed as a filter over the base
    /// series, to compare with the state machine.
    fn reference_search(t: u32, n: Option<u32>) -> Vec<u32> {
        let base = versions(LadderKind::Greatest, n);
        let included = |v: u32| n.is_some_and(|n| v <= n);
        let mut out = Vec::new();
        for v in base {
            out.push(v);
            if (included(v) && v > t) || (!included(v) && v <= t) {
                break;
            }
        }
        out
    }

    #[test]
    fn search_ladders_match_the_filtered_base_series() {
        for t in 0..80u32 {
            for n in std::iter::once(None).chain((0..120u32).map(Some)) {
                assert_eq!(search(t, n), reference_search(t, n), "t={t} n={n:?}");
            }
        }
        // Target 6 with greatest 6 runs the whole base series.
        assert_eq!(search(6, Some(6)), vec![0, 1, 3, 7, 5, 6]);
        // Greatest 9 above target 6: stops at the inclusion of 7.
        assert_eq!(search(6, Some(9)), vec![0, 1, 3, 7]);
        // Greatest 4 below target 6: stops at the non-inclusion of 5.
        assert_eq!(search(6, Some(4)), vec![0, 1, 3, 7, 5]);
        // No version: stops at the non-inclusion of 0.
        assert_eq!(search(6, None), vec![0]);
    }

    #[test]
    fn search_ladder_outcomes() {
        let end = drive(LadderKind::Search { target: 6 }, |v| Ok(v <= 9)).unwrap();
        assert!(end.above_target && !end.below_target_missing);
        let end = drive(LadderKind::Search { target: 6 }, |v| Ok(v <= 4)).unwrap();
        assert!(!end.above_target && end.below_target_missing);
        let end = drive(LadderKind::Search { target: 6 }, |v| Ok(v <= 6)).unwrap();
        assert!(!end.above_target && !end.below_target_missing);
        assert_eq!(end.exact_greatest(), Some(Some(6)));
    }

    #[test]
    fn monitoring_ladders() {
        // Appendix B: the base series for t, keeping versions <= t.
        for t in 0..300u32 {
            let expected: Vec<u32> = versions(LadderKind::Greatest, Some(t))
                .into_iter()
                .filter(|&v| v <= t)
                .collect();
            assert_eq!(
                versions(LadderKind::Monitor { target: t }, Some(t)),
                expected,
                "t={t}"
            );
            // The series does not depend on the truth: lookups above t are
            // never made.
            assert_eq!(
                versions(LadderKind::Monitor { target: t }, Some(t + 50)),
                expected
            );
        }
        assert_eq!(
            versions(LadderKind::Monitor { target: 6 }, Some(6)),
            vec![0, 1, 3, 5, 6]
        );
        // A missing version at or below the target is reported.
        let end = drive(LadderKind::Monitor { target: 6 }, |v| Ok(v != 3)).unwrap();
        assert!(end.below_target_missing);
    }

    #[test]
    fn lookup_errors_stop_the_ladder() {
        let out = drive(LadderKind::Greatest, |v| {
            if v == 3 {
                Err(Error::MalformedProof("ran out of results"))
            } else {
                Ok(true)
            }
        });
        assert_eq!(out, Err(Error::MalformedProof("ran out of results")));
    }
}
