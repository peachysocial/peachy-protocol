// SPDX-License-Identifier: MIT
//! The live lane's replay window (docs/calls.md §Signaling,
//! docs/calls.md D3).
//!
//! A live frame is sealed under the epoch's live key, which every member
//! holds, and the server relays it. Without a window the server (or anyone on
//! the path) could record a frame and send it again while the epoch lasts: a
//! replayed `Left` drops a participant's tile. So every live frame carries,
//! inside its AEAD, the sender's leaf and a stamp
//! ([`super::frame::LiveStamp`]), and each receiver remembers the stamps it
//! has accepted per (group, sender leaf), each under the call it came in.
//!
//! **The stamp** is the sender's agreed clock in milliseconds, made strictly
//! increasing per core: `max(now_ms, last + 1)`. A clock is used rather than
//! a bare counter so that a receiver that has no record yet (it just joined,
//! or restarted and lost the window it kept in memory) can still refuse an
//! old recording: anything more than [`CALL_LIVE_MAX_SKEW_MS`] from its own
//! clock, either way, is refused.
//!
//! **The rule**, per (group, sender leaf):
//! - a stamp more than [`CALL_LIVE_MAX_SKEW_MS`] from the receiver's clock is
//!   refused;
//! - a stamp already accepted in the same call is refused. The same stamp in
//!   another call is another frame: the call id is sealed inside the frame,
//!   so a recording cannot be sent again as another call's;
//! - any other stamp is accepted once, in whatever order it arrives. Two
//!   signals a device sends at once can ride two requests that the server
//!   serves out of order, and both are real;
//! - a frame from an older epoch than the sender's last accepted one is
//!   refused, and a newer epoch starts the sender afresh (its leaf may be a
//!   different device now, with a different clock). In practice the live key
//!   is current-epoch only (R-K9), so an older epoch's frame never opens
//!   anyway.
//!
//! There is no high-water mark. A stamp is remembered until the clock bound
//! would refuse it anyway, so a frame claiming another's leaf with a stamp
//! ahead of that leaf's clock takes that one stamp and nothing the leaf sends
//! later.
//!
//! **Expiry runs on the monotonic clock.** Each stamp is kept with the
//! receiver's monotonic time when it arrived, and forgotten only once
//! [`CALL_LIVE_FORGET_MS`] of monotonic time has passed since AND the wall
//! clock bound refuses it. A stamp the window accepted lay within
//! [`CALL_LIVE_MAX_SKEW_MS`] of the wall clock then, so on a clock that runs
//! true the bound refuses it again after twice that. A wall clock that steps
//! forward and back (a user setting it, a network time correction) then
//! forgets nothing early: a frame recorded before the step is still a
//! duplicate after it.
//!
//! **Bounded.** One record per (group, leaf), and the session opens a frame
//! only for a leaf in the tree, so a member cannot mint records by inventing
//! call ids. The window holds at most [`CALL_LIVE_MAX_SENDERS`] records and
//! [`MAX_SEEN`] stamps per record. Past either cap the oldest goes: the
//! record heard from least recently, or the stamp the record accepted
//! longest ago, never the one it has just accepted. A frame is recorded only
//! after its leaf's signature verifies, so only a leaf's own device adds
//! stamps to its record; a member can push out another leaf's record only by
//! being heard from at more leaves than the window holds, across the groups
//! this device shares with it.
//!
//! Every live frame is signed by the leaf it claims
//! ([`super::frame::live_signature_statement`]); the session refuses one that
//! carries no signature or whose signature does not verify under that leaf's
//! key, whatever the leaf, and refuses a live `Left` outright. So a member
//! cannot write a live frame for another member's leaf. The window is against
//! the network, and against the server only while a stamp is remembered: the
//! server sets the agreed clock, so once a stamp is forgotten it can move the
//! clock back and have that frame opened again within its epoch.
//!
//! The clock here is the core's agreed clock, its wall clock plus the
//! server's offset ([`crate::set_server_clock_offset_ms`]), so devices whose
//! wall clocks disagree still share a window.
//!
//! The window lives in the [`crate::Client`], in memory. It is not persisted:
//! a restart forgets it, so a receiver that restarts takes once a frame up to
//! the clock bound old that it had already seen.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::json;

use super::CALL_ID_BYTES;
use crate::error::{Error, Result};

/// How far a live frame's stamp may be from the receiver's agreed clock,
/// either way. Two minutes: wide enough for phones whose clocks are off by a
/// minute, and the longest a recording stays replayable to a receiver with no
/// record while the clock holds. The server sets the agreed clock, so by
/// moving it back it can have an older recording opened again within its
/// epoch.
pub const CALL_LIVE_MAX_SKEW_MS: u64 = 120_000;
/// The most records, one per (group, leaf), one window remembers.
pub const CALL_LIVE_MAX_SENDERS: usize = 1_024;
/// The most stamps one record holds. An honest device sends a heartbeat
/// every 10 s, so it has about 24 inside the clock bound.
pub const MAX_SEEN: usize = 256;
/// How long, on the receiver's monotonic clock, an accepted stamp is kept at
/// least: twice [`CALL_LIVE_MAX_SKEW_MS`], the most a stamp accepted ahead of
/// the wall clock needs before the bound refuses it as stale.
pub const CALL_LIVE_FORGET_MS: u64 = 2 * CALL_LIVE_MAX_SKEW_MS;
/// Why a live frame was refused. Each is a replay or as good as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveReplayVerdict {
    Accepted,
    /// This stamp from this sender was already accepted.
    Duplicate,
    /// From an epoch older than the one this sender was last heard in.
    OldEpoch,
    /// More than [`CALL_LIVE_MAX_SKEW_MS`] behind the receiver's clock.
    Stale,
    /// More than [`CALL_LIVE_MAX_SKEW_MS`] ahead of the receiver's clock.
    Future,
}

impl LiveReplayVerdict {
    /// Its name in the fixture.
    pub fn name(self) -> &'static str {
        match self {
            LiveReplayVerdict::Accepted => "accepted",
            LiveReplayVerdict::Duplicate => "duplicate",
            LiveReplayVerdict::OldEpoch => "oldEpoch",
            LiveReplayVerdict::Stale => "stale",
            LiveReplayVerdict::Future => "future",
        }
    }

    /// `Ok` for an accepted frame, else the refusal every client drops.
    pub fn into_result(self) -> Result<()> {
        match self {
            LiveReplayVerdict::Accepted => Ok(()),
            other => Err(Error::invalid(format!(
                "a live call signal was refused as a replay ({})",
                other.name()
            ))),
        }
    }
}

/// One accepted frame's mark: its call and its stamp.
type Mark = ([u8; CALL_ID_BYTES], u64);

#[derive(Debug, Clone, Default)]
struct Sender {
    epoch: u64,
    /// The receiver's monotonic clock when this sender was last accepted.
    heard_ms: u64,
    /// Accepted marks not yet expired, each with the receiver's monotonic
    /// clock when it arrived.
    seen: BTreeMap<Mark, u64>,
}

type SenderKey = (Vec<u8>, u32);

/// Every sender this receiver has accepted a live frame from, by (group,
/// sender leaf).
#[derive(Debug, Clone, Default)]
pub struct LiveReplayWindow {
    senders: BTreeMap<SenderKey, Sender>,
}

impl LiveReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check one frame and, when it is accepted, remember it. `now_ms` is
    /// the receiver's wall clock (the bound the stamp is checked against),
    /// `mono_ms` its monotonic clock (what an accepted stamp expires by).
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &mut self,
        group_id: &[u8],
        call_id: [u8; CALL_ID_BYTES],
        epoch: u64,
        sender_leaf: u32,
        stamp_ms: u64,
        now_ms: u64,
        mono_ms: u64,
    ) -> LiveReplayVerdict {
        if stamp_ms > now_ms.saturating_add(CALL_LIVE_MAX_SKEW_MS) {
            return LiveReplayVerdict::Future;
        }
        if stamp_ms.saturating_add(CALL_LIVE_MAX_SKEW_MS) < now_ms {
            return LiveReplayVerdict::Stale;
        }
        let mark = (call_id, stamp_ms);
        let key = (group_id.to_vec(), sender_leaf);
        if !self.senders.contains_key(&key) {
            self.make_room(now_ms, mono_ms);
        }
        let sender = self.senders.entry(key).or_default();
        forget_expired(&mut sender.seen, now_ms, mono_ms);
        if sender.seen.is_empty() || epoch > sender.epoch {
            *sender = Sender {
                epoch,
                heard_ms: mono_ms,
                seen: BTreeMap::from([(mark, mono_ms)]),
            };
            return LiveReplayVerdict::Accepted;
        }
        if epoch < sender.epoch {
            return LiveReplayVerdict::OldEpoch;
        }
        if sender.seen.contains_key(&mark) {
            return LiveReplayVerdict::Duplicate;
        }
        sender.seen.insert(mark, mono_ms);
        sender.heard_ms = mono_ms;
        // Past the cap the mark accepted longest ago goes, never this one.
        // By stamp order instead, a stamp below every one held would be
        // forgotten as it is accepted, and open again on every replay; a
        // member filling a leaf with stamps ahead of its clock would make
        // every frame the leaf really sends such a stamp.
        while sender.seen.len() > MAX_SEEN {
            let oldest = sender
                .seen
                .iter()
                .filter(|(held, _)| **held != mark)
                .min_by_key(|(held, arrived)| (**arrived, **held))
                .map(|(held, _)| *held);
            match oldest {
                Some(held) => {
                    sender.seen.remove(&held);
                }
                None => break,
            }
        }
        LiveReplayVerdict::Accepted
    }

    /// Before a new sender goes in: drop every sender whose stamps have all
    /// expired, and if the window is still full, the one heard from least
    /// recently.
    fn make_room(&mut self, now_ms: u64, mono_ms: u64) {
        if self.senders.len() < CALL_LIVE_MAX_SENDERS {
            return;
        }
        self.senders.retain(|_, sender| {
            forget_expired(&mut sender.seen, now_ms, mono_ms);
            !sender.seen.is_empty()
        });
        while self.senders.len() >= CALL_LIVE_MAX_SENDERS {
            let oldest = self
                .senders
                .iter()
                .min_by_key(|(_, sender)| sender.heard_ms)
                .map(|(key, _)| key.clone());
            match oldest {
                Some(key) => {
                    self.senders.remove(&key);
                }
                None => break,
            }
        }
    }

    /// How many senders the window remembers.
    pub fn senders(&self) -> usize {
        self.senders.len()
    }

    /// How many stamps the window remembers, over every sender.
    pub fn stamps(&self) -> usize {
        self.senders.values().map(|sender| sender.seen.len()).sum()
    }

    /// Forget a group's senders (it was left or forgotten).
    pub fn forget_group(&mut self, group_id: &[u8]) {
        self.senders.retain(|(group, _), _| group != group_id);
    }
}

/// Drop the marks that arrived [`CALL_LIVE_FORGET_MS`] ago or more on the
/// monotonic clock and that the wall clock bound refuses by now: a replay of
/// one is [`LiveReplayVerdict::Stale`] without the record, and stays so
/// unless the wall clock steps back by more than it ran.
fn forget_expired(seen: &mut BTreeMap<Mark, u64>, now_ms: u64, mono_ms: u64) {
    seen.retain(|(_, stamp), arrived| {
        let kept_long_enough = arrived.saturating_add(CALL_LIVE_FORGET_MS) < mono_ms;
        let stale_by_wall = stamp.saturating_add(CALL_LIVE_MAX_SKEW_MS) < now_ms;
        !(kept_long_enough && stale_by_wall)
    });
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Step {
    #[serde(default)]
    call_id: Option<String>,
    epoch: u64,
    leaf: u32,
    sent_at_ms: u64,
    now_ms: u64,
    /// The receiver's monotonic clock; the wall clock's when absent (a clock
    /// that never steps).
    #[serde(default)]
    mono_ms: Option<u64>,
}

/// The fixture's door: run `steps` (a JSON array of
/// `{"callId"?,"epoch","leaf","sentAtMs","nowMs","monoMs"?}`) through one
/// fresh window for one group and answer `{"verdicts":[…]}`, each a
/// [`LiveReplayVerdict::name`].
pub fn live_replay_steps_json(steps: &serde_json::Value) -> Result<serde_json::Value> {
    let steps: Vec<Step> = serde_json::from_value(steps.clone())
        .map_err(|err| Error::invalid(format!("could not read the replay steps: {err}")))?;
    let mut window = LiveReplayWindow::new();
    let mut verdicts = Vec::with_capacity(steps.len());
    for step in steps {
        let call_id = match step.call_id {
            Some(hex) => super::from_hex(&hex, "callId")?
                .as_slice()
                .try_into()
                .map_err(|_| Error::invalid("a call id is 16 bytes"))?,
            None => [0u8; CALL_ID_BYTES],
        };
        let verdict = window.check(
            b"fixture",
            call_id,
            step.epoch,
            step.leaf,
            step.sent_at_ms,
            step.now_ms,
            step.mono_ms.unwrap_or(step.now_ms),
        );
        verdicts.push(verdict.name());
    }
    Ok(json!({ "verdicts": verdicts }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_789_516_800_000;

    #[test]
    fn a_sender_refuses_what_it_has_seen_in_any_order() {
        let mut w = LiveReplayWindow::new();
        let mut check = |leaf, stamp, now| w.check(b"g", [1; 16], 3, leaf, stamp, now, now);
        assert_eq!(check(2, NOW, NOW), LiveReplayVerdict::Accepted);
        assert_eq!(check(2, NOW, NOW), LiveReplayVerdict::Duplicate);
        assert_eq!(check(2, NOW + 10, NOW), LiveReplayVerdict::Accepted);
        // Out of order: once, not twice.
        assert_eq!(check(2, NOW + 5, NOW), LiveReplayVerdict::Accepted);
        assert_eq!(check(2, NOW + 5, NOW), LiveReplayVerdict::Duplicate);
        // A stamp far below the newest is still unseen, and still accepted.
        assert_eq!(check(2, NOW - 60_000, NOW), LiveReplayVerdict::Accepted);
        // Another leaf has its own record.
        assert_eq!(check(3, NOW, NOW), LiveReplayVerdict::Accepted);
        // The clock bound.
        assert_eq!(check(4, NOW, NOW + 200_000), LiveReplayVerdict::Stale);
        assert_eq!(check(4, NOW + 200_000, NOW), LiveReplayVerdict::Future);
    }

    #[test]
    fn the_per_sender_cap_drops_the_stamp_accepted_longest_ago() {
        let mut w = LiveReplayWindow::new();
        for i in 0..=(MAX_SEEN as u64 + 10) {
            assert_eq!(
                w.check(b"g", [1; 16], 1, 0, NOW + i, NOW, NOW),
                LiveReplayVerdict::Accepted
            );
        }
        assert_eq!(w.stamps(), MAX_SEEN);
        assert_eq!(
            w.check(b"g", [1; 16], 1, 0, NOW + MAX_SEEN as u64 + 10, NOW, NOW),
            LiveReplayVerdict::Duplicate
        );
    }

    #[test]
    fn a_full_window_drops_the_sender_heard_from_least_recently() {
        let mut w = LiveReplayWindow::new();
        for leaf in 0..CALL_LIVE_MAX_SENDERS as u32 {
            let now = NOW + u64::from(leaf);
            w.check(b"g", [1; 16], 1, leaf, NOW, now, now);
        }
        assert_eq!(w.senders(), CALL_LIVE_MAX_SENDERS);
        let late = NOW + CALL_LIVE_MAX_SENDERS as u64;
        assert_eq!(
            w.check(b"h", [2; 16], 1, 0, late, late, late),
            LiveReplayVerdict::Accepted
        );
        assert_eq!(w.senders(), CALL_LIVE_MAX_SENDERS);
        // Leaf 0 went; leaf 1 is still remembered.
        assert_eq!(
            w.check(b"g", [1; 16], 1, 1, NOW, late, late),
            LiveReplayVerdict::Duplicate
        );
        assert_eq!(
            w.check(b"g", [1; 16], 1, 0, NOW, late, late),
            LiveReplayVerdict::Accepted
        );
    }

    fn call(i: u32) -> [u8; 16] {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&i.to_be_bytes());
        id
    }

    #[test]
    fn a_member_inventing_call_ids_fills_only_its_own_leafs_record() {
        let mut w = LiveReplayWindow::new();
        // A leaf sends one frame in its group.
        assert_eq!(
            w.check(b"a", [7; 16], 1, 5, NOW, NOW, NOW),
            LiveReplayVerdict::Accepted
        );
        // A member of another group sends frames for its own leaf under four
        // windows of fresh call ids, each heard after the leaf: they are one
        // record, holding its newest stamps.
        for i in 0..(4 * CALL_LIVE_MAX_SENDERS as u32) {
            let at = NOW + 1 + u64::from(i);
            assert_eq!(
                w.check(b"b", call(i), 1, 9, at, at, at),
                LiveReplayVerdict::Accepted
            );
        }
        assert_eq!(w.senders(), 2);
        assert_eq!(w.stamps(), 1 + MAX_SEEN);
        // The leaf's frame is still refused as a replay.
        let late = NOW + 10_000;
        assert_eq!(
            w.check(b"a", [7; 16], 1, 5, NOW, late, late),
            LiveReplayVerdict::Duplicate
        );
    }

    #[test]
    fn the_same_stamp_in_another_call_is_another_frame() {
        // One record per leaf, but a mark per call: the call id is sealed
        // inside the frame, so a device whose two cores stamped the same
        // millisecond in two calls loses neither frame.
        let mut w = LiveReplayWindow::new();
        assert_eq!(
            w.check(b"g", call(0), 1, 3, NOW, NOW, NOW),
            LiveReplayVerdict::Accepted
        );
        assert_eq!(
            w.check(b"g", call(1), 1, 3, NOW, NOW, NOW),
            LiveReplayVerdict::Accepted
        );
        assert_eq!(
            w.check(b"g", call(1), 1, 3, NOW, NOW, NOW),
            LiveReplayVerdict::Duplicate
        );
        assert_eq!(w.senders(), 1);
    }
    #[test]
    fn a_wall_clock_stepped_forward_and_back_forgets_nothing() {
        let mut w = LiveReplayWindow::new();
        let mono = 5_000;
        assert_eq!(
            w.check(b"g", [1; 16], 1, 0, NOW, NOW, mono),
            LiveReplayVerdict::Accepted
        );
        // The wall clock jumps three minutes ahead: the next frame is
        // accepted, and the first stamp, stale by the wall, is still kept.
        let ahead = NOW + 180_000;
        assert_eq!(
            w.check(b"g", [1; 16], 1, 0, ahead, ahead, mono + 10_000),
            LiveReplayVerdict::Accepted
        );
        // Stepped back: the first frame replayed is still a duplicate.
        assert_eq!(
            w.check(b"g", [1; 16], 1, 0, NOW, NOW + 20_000, mono + 20_000),
            LiveReplayVerdict::Duplicate
        );
    }

    #[test]
    fn a_stamp_goes_once_the_monotonic_clock_and_the_bound_both_let_it() {
        let mut w = LiveReplayWindow::new();
        assert_eq!(
            w.check(b"g", [1; 16], 1, 0, NOW, NOW, 0),
            LiveReplayVerdict::Accepted
        );
        let later = NOW + CALL_LIVE_FORGET_MS + 1;
        assert_eq!(
            w.check(b"g", [1; 16], 1, 0, later, later, CALL_LIVE_FORGET_MS + 1),
            LiveReplayVerdict::Accepted
        );
        assert_eq!(w.stamps(), 1);
    }
}
