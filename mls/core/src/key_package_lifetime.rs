// SPDX-License-Identifier: MIT
//! A KeyPackage's lifetime is checked by the member that adds it, on its own
//! clock (docs/identity.md §A KeyPackage's lifetime is checked by
//! its adder).
//!
//! The lifetime is a window its own device signs into every KeyPackage
//! (RFC 9420 §7.2). Every member that processes the Add judges it again on
//! its own clock, inside OpenMLS, with no switch to turn that off: a package
//! lapsing between a prompt member's read of its Add and a late member's has
//! the late member refuse a commit the rest merged. So the adder leaves no
//! honest reader that chance:
//!
//! - **A device mints** every package with OpenMLS's default window, an hour
//!   back and [`MINT_LIFETIME_SECONDS`] ahead.
//! - **The adder judges** a package before it commits it. OpenMLS refuses,
//!   on this device's clock, a window that has not started or has ended;
//!   [`check_at_adder`] then refuses, on that same clock, a window that
//!   started less than [`ADDER_BACKDATE_SECONDS`] ago, so every reader whose
//!   clock is up to that far behind the adder's finds it started too, and,
//!   on the core's clock, a window longer
//!   than the RFC's MUST maximum, or one that lives less than
//!   [`ADDER_HORIZON_SECONDS`] more, past the delivery service's thirty-day
//!   mailbox horizon, so no honest member reads the Add after the package
//!   lapses. Every package an honest build mints passes: it is backdated an
//!   hour, and an add refuses an expired credential, so the package was
//!   minted under a credential at most thirty-one days old and has at least
//!   fifty-three days left. One minted on a clock more than ten minutes
//!   ahead of the adder's waits that much longer to be added.
//! - **A joiner does not judge** the lifetimes in its Welcome's tree. Each
//!   was judged when its leaf was added, and a leaf whose member never
//!   renewed it would otherwise shut the group to every later join.

use openmls::prelude::{KeyPackage, Lifetime};

use crate::error::{Error, Result};

const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;

/// How far ahead of its minting a package lives: OpenMLS's default, twelve
/// weeks.
pub const MINT_LIFETIME_SECONDS: u64 = 84 * DAY;
/// How far back of its minting a package's window starts, for clocks that
/// run behind the minter's: OpenMLS's default, an hour.
pub const MINT_BACKDATE_SECONDS: u64 = HOUR;
/// The longest total window a package may claim (RFC 9420 §7.2: "Applications
/// MUST define a maximum total lifetime"): what a device mints, and the same
/// value as OpenMLS's own `MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS`, which it
/// does not apply to a package it is handed.
pub const MAX_LIFETIME_RANGE_SECONDS: u64 = MINT_LIFETIME_SECONDS + MINT_BACKDATE_SECONDS;
/// How long before the adder's now a package's window must have started:
/// most of the hour every device backdates by, so a reader whose clock lags
/// the adder's by up to this much still finds the window started.
pub const ADDER_BACKDATE_SECONDS: u64 = 50 * 60;
/// How long a package must still live when it is added: past the thirty days
/// a commit waits in a device's mailbox (docs/delivery.md §Retention),
/// so no honest member reads the Add after the package lapses.
pub const ADDER_HORIZON_SECONDS: u64 = 31 * DAY;

/// The adder's verdict on `key_package`, at its own `now`, and at the wall
/// clock OpenMLS judges a window's start by (on the adder and on every
/// reader alike).
pub(crate) fn check_at_adder(key_package: &KeyPackage, now: i64) -> Result<()> {
    // OpenMLS's own clock: a window of no length ends there.
    let wall = Lifetime::new(0).not_after();
    verdict(key_package.life_time(), now, wall)
}

/// A window no longer than [`MAX_LIFETIME_RANGE_SECONDS`] that started at
/// least [`ADDER_BACKDATE_SECONDS`] before `wall` and lives at least
/// [`ADDER_HORIZON_SECONDS`] past `now`.
fn verdict(lifetime: &Lifetime, now: i64, wall: u64) -> Result<()> {
    if lifetime.not_before() > wall.saturating_sub(ADDER_BACKDATE_SECONDS) {
        return Err(Error::invalid(
            "that KeyPackage's lifetime started too recently to be added",
        ));
    }
    if lifetime.not_after() < lifetime.not_before()
        || lifetime.not_after() - lifetime.not_before() > MAX_LIFETIME_RANGE_SECONDS
    {
        return Err(Error::invalid(
            "that KeyPackage claims a lifetime longer than any device mints",
        ));
    }
    let now = u64::try_from(now).unwrap_or(0);
    if lifetime.not_after() < now.saturating_add(ADDER_HORIZON_SECONDS) {
        return Err(Error::invalid(
            "that KeyPackage's lifetime ends too soon to be added",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-09-16T00:00:00Z: any instant would do.
    const NOW: u64 = 1_789_516_800;

    fn judged(not_before: u64, not_after: u64) -> bool {
        verdict(
            &Lifetime::init(not_before, not_after),
            i64::try_from(NOW).unwrap_or(0),
            NOW,
        )
        .is_ok()
    }

    #[test]
    fn a_window_that_started_less_than_fifty_minutes_ago_is_refused() {
        let end = NOW + MINT_LIFETIME_SECONDS;
        assert!(!judged(NOW, end));
        assert!(!judged(NOW - ADDER_BACKDATE_SECONDS + 1, end));
        assert!(judged(NOW - ADDER_BACKDATE_SECONDS, end));
    }

    #[test]
    fn a_freshly_minted_window_passes() {
        assert!(judged(
            NOW - MINT_BACKDATE_SECONDS,
            NOW + MINT_LIFETIME_SECONDS
        ));
    }

    #[test]
    fn a_window_minted_fifty_three_days_ago_still_passes() {
        let minted = NOW - 53 * DAY;
        assert!(judged(
            minted - MINT_BACKDATE_SECONDS,
            minted + MINT_LIFETIME_SECONDS
        ));
    }

    #[test]
    fn a_window_lapsing_inside_the_mailbox_horizon_is_refused() {
        assert!(!judged(NOW - HOUR, NOW + 3));
        assert!(!judged(NOW - HOUR, NOW + ADDER_HORIZON_SECONDS - 1));
        assert!(judged(NOW - HOUR, NOW + ADDER_HORIZON_SECONDS));
    }

    #[test]
    fn a_window_longer_than_any_device_mints_is_refused() {
        assert!(!judged(
            NOW - HOUR,
            NOW - HOUR + MAX_LIFETIME_RANGE_SECONDS + 1
        ));
        assert!(judged(NOW - HOUR, NOW - HOUR + MAX_LIFETIME_RANGE_SECONDS));
        assert!(!judged(NOW + DAY, NOW));
    }
}
