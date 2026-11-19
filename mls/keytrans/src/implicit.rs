// SPDX-License-Identifier: MIT
//! The implicit binary search tree over log entries
//! (draft-ietf-keytrans-protocol-05 §4.1, Appendix A), the frontier, the
//! entries a view update needs (§4.2), and distinguished entries (§6.1).
//!
//! Positions are log entry indices. A tree of `n` entries has its root at
//! `2^floor(log2(n)) - 1`; an entry's level is its number of trailing one
//! bits, and its children are found by bit arithmetic, stepping left while a
//! right child would fall past the end of the log.

use crate::error::{Error, Result};

/// `floor(log2(x))`, and 0 for 0.
pub fn log2(x: u64) -> u32 {
    if x == 0 {
        0
    } else {
        63 - x.leading_zeros()
    }
}

/// An entry's level: 0 for even positions, else its count of trailing ones.
pub fn level(x: u64) -> u32 {
    x.trailing_ones()
}

/// The root of the implicit tree of `n` entries.
pub fn root(n: u64) -> Result<u64> {
    if n == 0 {
        return Err(Error::InvalidArgument("an empty log has no root"));
    }
    Ok((1u64 << log2(n)) - 1)
}

/// `x`'s left child, if it has one (it has one iff its level is above 0).
pub fn left(x: u64) -> Option<u64> {
    let k = level(x);
    if k == 0 {
        None
    } else {
        Some(x ^ (1u64 << (k - 1)))
    }
}

/// `x`'s right child in the tree of `n` entries, if it has one.
pub fn right(x: u64, n: u64) -> Option<u64> {
    let k = level(x);
    if k == 0 || k >= 64 {
        return None;
    }
    // The right child in the perfect tree is x + 2^(k-1); while that lies
    // past the log, its left child stands in for it.
    let mut y = x ^ (3u64 << (k - 1));
    while y >= n {
        y = left(y)?;
    }
    Some(y)
}

/// `x`'s parent in the tree of `n` entries, if `x` is not the root.
pub fn parent(x: u64, n: u64) -> Result<Option<u64>> {
    let r = root(n)?;
    if x >= n {
        return Err(Error::InvalidArgument("entry outside the log"));
    }
    if x == r {
        return Ok(None);
    }
    let mut y = x;
    loop {
        // In the perfect tree, a node of level k is a left child when bit
        // k+1 is clear (its parent is x + 2^k), a right child otherwise.
        let k = level(y);
        if k >= 63 {
            return Err(Error::InvalidArgument("entry has no parent"));
        }
        let step = 1u64 << k;
        y = if y & (step << 1) == 0 {
            y + step
        } else {
            y - step
        };
        if y < n {
            return Ok(Some(y));
        }
    }
}

/// `x`'s ancestors in the tree of `n` entries, nearest first.
pub fn ancestors(x: u64, n: u64) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    let mut y = x;
    while let Some(p) = parent(y, n)? {
        out.push(p);
        y = p;
    }
    Ok(out)
}

/// The frontier of `n` entries (§4.1): the root, its right child, that
/// one's right child, and so on to entry `n - 1`. Empty for 0.
pub fn frontier(n: u64) -> Vec<u64> {
    let Ok(mut x) = root(n) else {
        return Vec::new();
    };
    let mut out = vec![x];
    while let Some(next) = right(x, n) {
        out.push(next);
        x = next;
    }
    out
}

/// The entries whose timestamps a response carries so a user who verified
/// `retained` entries can move to `n` (§4.2, §12.3.1), in the order the
/// response lists them. With nothing retained, the frontier; with as many
/// as `n` or more, nothing.
pub fn update_view(n: u64, retained: Option<u64>) -> Result<Vec<u64>> {
    let m = match retained {
        None | Some(0) => return Ok(frontier(n)),
        Some(m) if m >= n => return Ok(Vec::new()),
        Some(m) => m,
    };
    // The ancestors of entry m-1 in the new tree that lie at or after m,
    // nearest first. The last is on the new frontier.
    let mut out: Vec<u64> = ancestors(m - 1, n)?
        .into_iter()
        .filter(|&a| a >= m)
        .collect();
    let mut last = match out.last() {
        Some(&a) => a,
        // m-1 is itself on the new frontier: continue from its right child.
        None => {
            let next = right(m - 1, n)
                .ok_or(Error::InvalidArgument("no entry after the retained ones"))?;
            out.push(next);
            next
        }
    };
    while let Some(next) = right(last, n) {
        out.push(next);
        last = next;
    }
    Ok(out)
}

/// The test of §6.1 step 2: an entry between a left and a right timestamp
/// is distinguished unless they are less than a reasonable monitoring
/// window apart.
pub fn spans_window(left_timestamp: u64, right_timestamp: u64, window: u64) -> bool {
    right_timestamp.saturating_sub(left_timestamp) >= window
}

/// Every distinguished entry of a log of `n` entries, in position order,
/// with `timestamp` giving any entry's timestamp (§6.1). The prover's walk;
/// it reads one timestamp per distinguished entry and its children.
pub fn distinguished_entries(
    n: u64,
    window: u64,
    mut timestamp: impl FnMut(u64) -> Result<u64>,
) -> Result<Vec<u64>> {
    let Ok(r) = root(n) else {
        return Ok(Vec::new());
    };
    let rightmost = timestamp(n - 1)?;
    let mut out = Vec::new();
    // Depth-first, in order, with an explicit stack of (entry, left, right).
    let mut stack = vec![(r, 0u64, rightmost, false)];
    while let Some((x, lt, rt, expanded)) = stack.pop() {
        if expanded {
            out.push(x);
            continue;
        }
        if !spans_window(lt, rt, window) {
            continue;
        }
        let tx = timestamp(x)?;
        if let Some(rc) = right(x, n) {
            stack.push((rc, tx, rt, false));
        }
        stack.push((x, lt, rt, true));
        if let Some(lc) = left(x) {
            stack.push((lc, lt, tx, false));
        }
    }
    Ok(out)
}

/// The rightmost distinguished entry of `n` entries, if any (§6.3). It lies
/// on the frontier, so `timestamp` is only asked for frontier entries,
/// which a user retains.
pub fn rightmost_distinguished(
    n: u64,
    window: u64,
    mut timestamp: impl FnMut(u64) -> Result<u64>,
) -> Result<Option<u64>> {
    let Ok(mut x) = root(n) else {
        return Ok(None);
    };
    let rightmost = timestamp(n - 1)?;
    let mut lt = 0;
    let mut found = None;
    loop {
        if !spans_window(lt, rightmost, window) {
            return Ok(found);
        }
        found = Some(x);
        let Some(next) = right(x, n) else {
            return Ok(found);
        };
        lt = timestamp(x)?;
        x = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tree by its inductive definition (§4.1): root, then the left
    /// subtree over [lo, root) and the right over (root, hi).
    fn reference(
        lo: u64,
        hi: u64,
        parent_of: &mut Vec<Option<u64>>,
        up: Option<u64>,
    ) -> Option<u64> {
        if lo >= hi {
            return None;
        }
        let r = lo + root(hi - lo).unwrap();
        parent_of[r as usize] = up;
        reference(lo, r, parent_of, Some(r));
        reference(r + 1, hi, parent_of, Some(r));
        Some(r)
    }

    #[test]
    fn appendix_a_shapes() {
        assert_eq!(log2(0), 0);
        assert_eq!(log2(1), 0);
        assert_eq!(log2(50), 5);
        assert_eq!(log2(u64::MAX), 63);
        assert_eq!(level(6), 0);
        assert_eq!(level(7), 3);
        assert_eq!(root(50).unwrap(), 31);
        assert_eq!(root(14).unwrap(), 7);
        assert!(root(0).is_err());
        assert_eq!(left(7), Some(3));
        assert_eq!(left(4), None);
        assert_eq!(right(7, 14), Some(11));
        assert_eq!(right(11, 14), Some(13));
        assert_eq!(right(13, 14), None);
        assert_eq!(right(3, 4), None);
        // §4.1's example: 50 entries have frontier 31, 47, 49.
        assert_eq!(frontier(50), vec![31, 47, 49]);
        assert_eq!(frontier(1), vec![0]);
        assert_eq!(frontier(0), Vec::<u64>::new());
    }

    #[test]
    fn navigation_matches_the_inductive_definition() {
        for n in 1..=200u64 {
            let mut parent_of = vec![None; n as usize];
            let r = reference(0, n, &mut parent_of, None).unwrap();
            assert_eq!(root(n).unwrap(), r);
            for x in 0..n {
                assert_eq!(parent(x, n).unwrap(), parent_of[x as usize], "n={n} x={x}");
                let kids: Vec<u64> = (0..n)
                    .filter(|&c| parent_of[c as usize] == Some(x))
                    .collect();
                let l = kids.iter().copied().find(|&c| c < x);
                let rc = kids.iter().copied().find(|&c| c > x);
                assert_eq!(left(x), l, "left n={n} x={x}");
                assert_eq!(right(x, n), rc, "right n={n} x={x}");
            }
            assert!(parent(n, n).is_err());
        }
    }

    #[test]
    fn update_view_lists() {
        // From 0 to 50: the frontier.
        assert_eq!(update_view(50, None).unwrap(), vec![31, 47, 49]);
        assert_eq!(update_view(50, Some(0)).unwrap(), vec![31, 47, 49]);
        assert_eq!(update_view(50, Some(50)).unwrap(), Vec::<u64>::new());
        // From 40 to 50: 39's ancestors at or after 40 are 47; then 49.
        assert_eq!(update_view(50, Some(40)).unwrap(), vec![47, 49]);
        // From 32 to 50: 31 is on the new frontier; its right child, then on.
        assert_eq!(update_view(50, Some(32)).unwrap(), vec![47, 49]);
        // From 31 to 50: 30's ancestors at or after 31 include 31.
        assert_eq!(update_view(50, Some(31)).unwrap(), vec![31, 47, 49]);
        for n in 1..=130u64 {
            for m in 1..n {
                let v = update_view(n, Some(m)).unwrap();
                // Every listed entry is new, the list ends at n-1, and its
                // tail from the first frontier entry is the frontier's tail.
                assert!(v.iter().all(|&x| x >= m && x < n), "n={n} m={m}");
                assert_eq!(*v.last().unwrap(), n - 1);
                let f = frontier(n);
                let start = v.iter().position(|x| f.contains(x)).unwrap();
                let fi = f.iter().position(|x| *x == v[start]).unwrap();
                assert_eq!(&v[start..], &f[fi..]);
            }
        }
    }

    #[test]
    fn distinguished_walk() {
        // Entries one hour apart, a two-hour window.
        let hour = 3_600_000u64;
        let ts = |x: u64| Ok(x * hour);
        let n = 50;
        let all = distinguished_entries(n, 2 * hour, ts).unwrap();
        // Brute force over the definition.
        fn rec(x: u64, n: u64, lt: u64, rt: u64, w: u64, out: &mut Vec<u64>) {
            if rt.saturating_sub(lt) < w {
                return;
            }
            let tx = x * 3_600_000;
            if let Some(l) = left(x) {
                rec(l, n, lt, tx, w, out);
            }
            out.push(x);
            if let Some(r) = right(x, n) {
                rec(r, n, tx, rt, w, out);
            }
        }
        let mut expected = Vec::new();
        rec(
            root(n).unwrap(),
            n,
            0,
            (n - 1) * hour,
            2 * hour,
            &mut expected,
        );
        assert_eq!(all, expected);
        assert!(all.windows(2).all(|w| w[0] < w[1]));
        let rightmost = rightmost_distinguished(n, 2 * hour, ts).unwrap();
        assert_eq!(rightmost, all.last().copied());

        // A window of zero makes every entry distinguished.
        assert_eq!(
            distinguished_entries(10, 0, ts).unwrap(),
            (0..10).collect::<Vec<_>>()
        );
        assert_eq!(rightmost_distinguished(10, 0, ts).unwrap(), Some(9));
        // A window longer than the log's life makes none.
        assert_eq!(
            distinguished_entries(10, 100 * hour, ts).unwrap(),
            Vec::<u64>::new()
        );
        assert_eq!(rightmost_distinguished(10, 100 * hour, ts).unwrap(), None);
        assert_eq!(rightmost_distinguished(0, 0, ts).unwrap(), None);
    }

    #[test]
    fn distinguished_entries_are_stable_as_the_log_grows() {
        let ts = |x: u64| Ok(x * 1000 + (x % 7) * 13);
        let mut previous: Vec<u64> = Vec::new();
        for n in 1..=300u64 {
            let now = distinguished_entries(n, 10_000, ts).unwrap();
            assert!(previous.iter().all(|x| now.contains(x)), "n={n}");
            let rightmost = rightmost_distinguished(n, 10_000, ts).unwrap();
            assert_eq!(rightmost, now.last().copied());
            previous = now;
        }
    }
}
