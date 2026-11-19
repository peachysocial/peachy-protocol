// SPDX-License-Identifier: MIT
//! GROUP RECOVERY: what a device does when its copy of a group falls behind
//! the group's head or forks off it (docs/delivery.md §A commit the
//! server refuses, §A message that will not open, §The client contract on
//! `behind_retention`).
//!
//! One driver for every client, so Peachy's apps, the SDK and a client built
//! on the specs alone recover the same way. The client feeds it what only the
//! client can see (a head it read, a drain that ran to the end, a message
//! that would not open) and it answers what to do: nothing, catch up from the
//! mailbox, keep the copy, wait, or forget the group and ask back in with a
//! sealed seat ask. The network stays the client's: the driver reads no head
//! and sends nothing.
//!
//! ## The calls
//!
//! ```text
//! a message or commit failed to open (STALE_COPY among them):
//!     if read_due(group, sealed_ahead, now)        → read the head below
//! a drain ran to the end:
//!     for group in drain_complete(started, evidence, now) → read the head below
//! a refused commit of this device's own, a stale open, a lost mailbox:
//!     → read the head below
//!
//! read the head:
//!     begin(group)                                 → READ_HEAD, HELD or NO_COPY
//!     head = FetchConversationHead (begun after begin)
//!     judge(group, kind, head, fresh, now)         → the step
//! ```
//!
//! `begin` snapshots the copy's epoch, its verifier and the last complete
//! drain BEFORE the head is read: a head is judged against what the copy
//! held when the read began, never against a copy that moved under it.
//!
//! ## The steps
//!
//! | Step | Do |
//! |---|---|
//! | `IN_STEP` | nothing: the copy is the head's, or the reading proves nothing |
//! | `BEHIND` | catch up from the mailbox; the driver asks for the head again after the next complete drain |
//! | `ROLLED_BACK` | keep the copy: the server moved its head back below it |
//! | `HELD` | the group is held for its steward: every rejoin waits |
//! | `HOLD_ENTERED` | the driver just held the group: fetch the missing commit, read the head at the hold's cap |
//! | `REJOIN_FORKED`, `REJOIN_STUCK`, `REJOIN_LOST` | forget the group and ask back in |
//! | `BACKOFF` | a fork rejoin is due, and the last one was too recent: wait |
//! | `NO_COPY` | no active copy here |
//! | `READ_AGAIN` | a head below the copy from a read that may predate it: read a fresh one, judge again |
//! | `READ_HEAD` | (`begin` only) read the head, then judge |
//! | `SETTLE_FIRST` | a rejoin is due over a saved commit: settle it by `FetchVerifierAt` at the copy's epoch plus one, then read the head again |
//!
//! The rules themselves, below, are the apps' own, held by
//! `mls/fixtures/formats/commit-refusal.json`, which `tests/recovery.rs`
//! replays against this module.
//!
//! ## In memory, per client
//!
//! The counts (stuck behind, the fork backoff, the minute's head read) live
//! in the [`crate::Client`], not the store, as they always did in the apps: a
//! restart may rejoin once more, or wait one more window, never rejoin on a
//! stale count. The time of the last head read is kept in the store
//! ([`crate::Client::note_head_read`]).

use std::collections::BTreeMap;

/// The wait after one fork rejoin, before another may rejoin the same group.
pub const FORK_REJOIN_FIRST_MS: i64 = 10 * 60_000;
/// The longest wait, however many rejoins.
pub const FORK_REJOIN_CAP_MS: i64 = 6 * 60 * 60_000;
/// How long a group may read `behind` at one local epoch before it is stranded.
pub const STUCK_BEHIND_MS: i64 = 5 * 60_000;
/// And across at least this many readings.
pub const STUCK_BEHIND_CHECKS: u32 = 3;
/// A run of readings older than this starts over: far-apart readings never add up.
pub const STUCK_BEHIND_WINDOW_MS: i64 = 30 * 60_000;
/// At most one head read per group per this long over messages that would
/// not open, unless a message sealed past the copy's epoch asks and the last
/// read did not know of one.
pub const UNOPENED_READ_EVERY_MS: i64 = 60_000;

/// The Connect codes, in wire spelling, whose `SubmitCommit` refusal is worth
/// a head read. Any other code says nothing about the copy.
pub const CHECKED_REFUSAL_CODES: [&str; 2] = ["failed_precondition", "permission_denied"];

/// Whether a `SubmitCommit` refusal with this Connect code is worth reading
/// the group's head over.
pub fn refusal_worth_checking(code: &str) -> bool {
    CHECKED_REFUSAL_CODES.contains(&code)
}

/// What the driver says to do. Stable numbers: the C ABI's
/// `PEACHY_MLS_RECOVERY_*`, the bindings' and the docs'.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum RecoveryStep {
    /// Nothing: the copy is the head's, or the reading proves nothing.
    InStep = 0,
    /// The head is ahead: catch up from the mailbox. If the commit that would
    /// carry the copy up is not there, the next readings strand it.
    Behind = 1,
    /// The head is below the copy, at an epoch the group's own head once
    /// stood above on this copy: the server moved its head back. Keep the
    /// copy; neither forget the group nor ask back in.
    RolledBack = 2,
    /// The group is held for its steward: every rejoin path waits.
    Held = 3,
    /// The driver just held the group for its steward over a missing commit:
    /// fetch it (FetchCommitAt) and read the head again at the hold's cap.
    HoldEntered = 4,
    /// The copy is not on the head's branch: forget the group and ask back in.
    RejoinForked = 5,
    /// The copy is behind and nothing will carry it up: forget the group and
    /// ask back in.
    RejoinStuck = 6,
    /// After a lost mailbox, the copy is behind: forget the group and ask back in.
    RejoinLost = 7,
    /// A rejoin is due, and the last fork rejoin of the group was too recent.
    Backoff = 8,
    /// This device holds no active copy of the group.
    NoCopy = 9,
    /// The head read is below the copy and may be older than it: read a head
    /// begun after [`crate::Client::recovery_begin`], and judge again.
    ReadAgain = 10,
    /// From [`crate::Client::recovery_begin`]: read the head, then judge it.
    ReadHead = 11,
    /// A rejoin is due, and the group holds a SAVED commit
    /// ([`crate::Client::has_saved_commit`]) that forgetting it would drop
    /// unheard. Settle it first: read the verifier the server logged at the
    /// copy's epoch plus one (`FetchVerifierAt`) and hand it to
    /// [`crate::Client::settle_saved_commit`] as the head at that epoch,
    /// which merges the commit if it is the one taken and clears it if not;
    /// then read the head again. No backoff is spent.
    SettleFirst = 12,
}

impl RecoveryStep {
    /// Every step, in discriminant order.
    pub const ALL: [RecoveryStep; 13] = [
        Self::InStep,
        Self::Behind,
        Self::RolledBack,
        Self::Held,
        Self::HoldEntered,
        Self::RejoinForked,
        Self::RejoinStuck,
        Self::RejoinLost,
        Self::Backoff,
        Self::NoCopy,
        Self::ReadAgain,
        Self::ReadHead,
        Self::SettleFirst,
    ];

    /// The stable number.
    pub fn code(self) -> u32 {
        self as u32
    }

    /// A short, stable name, for logs and the bindings.
    pub fn name(self) -> &'static str {
        match self {
            Self::InStep => "in_step",
            Self::Behind => "behind",
            Self::RolledBack => "rolled_back",
            Self::Held => "held",
            Self::HoldEntered => "hold_entered",
            Self::RejoinForked => "rejoin_forked",
            Self::RejoinStuck => "rejoin_stuck",
            Self::RejoinLost => "rejoin_lost",
            Self::Backoff => "backoff",
            Self::NoCopy => "no_copy",
            Self::ReadAgain => "read_again",
            Self::ReadHead => "read_head",
            Self::SettleFirst => "settle_first",
        }
    }

    /// Whether the step says to forget the group and ask back in.
    pub fn rejoins(self) -> bool {
        matches!(
            self,
            Self::RejoinForked | Self::RejoinStuck | Self::RejoinLost
        )
    }
}

/// Why the head was read: what the driver judges it for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum HeadReadKind {
    /// The fork check: after a refused commit of this device's own, messages
    /// that would not open, a second reading a drain owes, a stale open, or a
    /// client's own schedule. Behind, forked and rolled back are all judged.
    Check = 0,
    /// The fork check, when a message sealed past the copy's epoch is known
    /// (`STALE_COPY`): a `behind` reading strands the copy at once, since
    /// the commit that would carry it up came before that message and did
    /// not apply.
    SealedAhead = 1,
    /// After a lost mailbox (`FetchMailboxResponse.lost`), an envelope that
    /// opened for no group, or a hold that reached its cap: a copy behind
    /// the head rejoins at once. Nothing else is judged.
    Lost = 2,
}

impl HeadReadKind {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Check),
            1 => Some(Self::SealedAhead),
            2 => Some(Self::Lost),
            _ => None,
        }
    }
}

/// A head as the delivery service reported it (`ConversationHead`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadReading {
    pub epoch: u64,
    /// The head's verifier: `SHA-256` of the send key at `epoch`. Any length
    /// but 32 is none.
    pub verifier: Vec<u8>,
}

/// What a head says of a copy, before any count or backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadVerdict {
    /// Nothing to act on: no head, a head with no verifier at the copy's
    /// epoch, or the copy's own verifier there.
    Level,
    /// The head is ahead of the copy.
    Behind,
    /// The copy is not on the head's branch.
    Forked,
    /// The head moved back below a copy that came through it.
    RolledBack,
}

/// THE FORK CHECK'S TABLE (docs/delivery.md §A commit the server
/// refuses). `head_epoch` `None`: the server holds no head.
/// `verifier_matches` `None`: the head carried no verifier.
/// `rolled_back`: [`crate::Client::head_rolled_back`] for this head, read
/// only for a head below the copy.
pub fn head_verdict(
    local_epoch: u64,
    head_epoch: Option<u64>,
    verifier_matches: Option<bool>,
    rolled_back: bool,
) -> HeadVerdict {
    let Some(head) = head_epoch else {
        return HeadVerdict::Level;
    };
    if head > local_epoch {
        return HeadVerdict::Behind;
    }
    if head < local_epoch {
        return if rolled_back {
            HeadVerdict::RolledBack
        } else {
            HeadVerdict::Forked
        };
    }
    match verifier_matches {
        Some(false) => HeadVerdict::Forked,
        _ => HeadVerdict::Level,
    }
}

/// How long after the last fork rejoin another may go ahead, after
/// `rejoins` so far: none for the first, then ten minutes, doubling, at most
/// six hours.
pub fn fork_rejoin_delay_ms(rejoins: u32) -> i64 {
    if rejoins == 0 {
        return 0;
    }
    let mut delay = FORK_REJOIN_FIRST_MS;
    for _ in 1..rejoins {
        delay = delay.saturating_mul(2);
        if delay >= FORK_REJOIN_CAP_MS {
            return FORK_REJOIN_CAP_MS;
        }
    }
    delay.min(FORK_REJOIN_CAP_MS)
}

/// Whether a commit whose submit THREW was taken anyway: the head is exactly
/// one past the epoch it was built at, under the verifier it carried; or the
/// head has moved further on and the verifier the server LOGGED at that next
/// epoch (FetchVerifierAt) is its. `logged_verifier_is_next` `None`: the log
/// could not be read or holds no row there, which proves nothing.
pub fn commit_was_taken(
    commit_epoch: u64,
    head_epoch: Option<u64>,
    head_verifier_is_next: Option<bool>,
    logged_verifier_is_next: Option<bool>,
) -> bool {
    let Some(head) = head_epoch else {
        return false;
    };
    let next = commit_epoch.saturating_add(1);
    if head == next {
        return head_verifier_is_next == Some(true);
    }
    if head > next {
        return logged_verifier_is_next == Some(true);
    }
    false
}

/// Fork rejoins per group, rate-limited ([`fork_rejoin_delay_ms`]). Never
/// forgotten while the client lives: a group that forks again and again is
/// exactly the one to slow down.
#[derive(Debug, Default, Clone)]
pub struct ForkRejoins {
    done: BTreeMap<Vec<u8>, (u32, i64)>,
}

impl ForkRejoins {
    /// Whether a fork may rejoin this group at `now_ms`.
    pub fn may_rejoin(&self, group_id: &[u8], now_ms: i64) -> bool {
        match self.done.get(group_id) {
            None => true,
            Some((count, at_ms)) => now_ms.saturating_sub(*at_ms) >= fork_rejoin_delay_ms(*count),
        }
    }

    /// A rejoin of this group went ahead at `now_ms`.
    pub fn note(&mut self, group_id: &[u8], now_ms: i64) {
        let count = self.done.get(group_id).map_or(0, |(count, _)| *count);
        self.done
            .insert(group_id.to_vec(), (count.saturating_add(1), now_ms));
    }
}

#[derive(Debug, Clone, Copy)]
struct BehindRun {
    epoch: u64,
    first_ms: i64,
    last_ms: i64,
    checks: u32,
}

/// `behind` readings per group, at the local epoch each was read at
/// (docs/delivery.md §A commit the server refuses, "Behind that
/// does not clear is stranded"):
///
/// 1. three readings at one epoch over at least five minutes strand it
///    (readings more than 30 minutes apart start over);
/// 2. a second reading at the same epoch after a whole drain that began
///    after the first strands it at once: the server moves the head and
///    places the commit's envelopes in one step, so that drain held whatever
///    could carry the copy up;
/// 3. a reading that strands nothing is owed a second one after the next
///    complete drain that begins after it ([`Self::recheck_after_drain`]).
#[derive(Debug, Default, Clone)]
pub struct StuckBehind {
    seen: BTreeMap<Vec<u8>, BehindRun>,
    owed: BTreeMap<Vec<u8>, i64>,
}

impl StuckBehind {
    /// A reading said `behind` at `local_epoch`. Answers whether the group is
    /// now stranded there. `last_drain_started_at_ms`: when the last drain
    /// that ran to the end began, read BEFORE `local_epoch` was; `None` when
    /// none has.
    pub fn note_behind(
        &mut self,
        group_id: &[u8],
        local_epoch: u64,
        now_ms: i64,
        last_drain_started_at_ms: Option<i64>,
    ) -> bool {
        let stuck = self.judge(group_id, local_epoch, now_ms, last_drain_started_at_ms);
        if stuck {
            self.owed.remove(group_id);
        } else {
            self.owed.insert(group_id.to_vec(), now_ms);
        }
        stuck
    }

    fn judge(
        &mut self,
        group_id: &[u8],
        epoch: u64,
        now_ms: i64,
        last_drain_started_at_ms: Option<i64>,
    ) -> bool {
        let fresh = BehindRun {
            epoch,
            first_ms: now_ms,
            last_ms: now_ms,
            checks: 1,
        };
        let Some(run) = self.seen.get_mut(group_id) else {
            self.seen.insert(group_id.to_vec(), fresh);
            return false;
        };
        if run.epoch != epoch || now_ms.saturating_sub(run.first_ms) > STUCK_BEHIND_WINDOW_MS {
            *run = fresh;
            return false;
        }
        let drained_since = last_drain_started_at_ms.is_some_and(|at| at > run.last_ms);
        run.checks = run.checks.saturating_add(1);
        run.last_ms = now_ms;
        if drained_since {
            return true;
        }
        run.checks >= STUCK_BEHIND_CHECKS && now_ms.saturating_sub(run.first_ms) >= STUCK_BEHIND_MS
    }

    /// A drain that began at `drain_started_at_ms` ran to the end: the groups
    /// whose last `behind` reading stranded nothing and came before it, each
    /// handed out once, to be read again now.
    pub fn recheck_after_drain(&mut self, drain_started_at_ms: i64) -> Vec<Vec<u8>> {
        let due: Vec<Vec<u8>> = self
            .owed
            .iter()
            .filter(|(_, at)| drain_started_at_ms > **at)
            .map(|(group, _)| group.clone())
            .collect();
        for group in &due {
            self.owed.remove(group);
        }
        due
    }

    /// Any other verdict, or a rejoin: start over.
    pub fn clear(&mut self, group_id: &[u8]) {
        self.seen.remove(group_id);
        self.owed.remove(group_id);
    }
}

/// What [`crate::Client::recovery_begin`] snapshot for one group.
#[derive(Debug, Clone)]
pub(crate) struct Probe {
    pub(crate) epoch: u64,
    pub(crate) verifier: [u8; 32],
    pub(crate) drain_mark: Option<i64>,
}

/// The driver's memory, one per [`crate::Client`].
#[derive(Debug, Default, Clone)]
pub(crate) struct RecoveryBook {
    pub(crate) stuck: StuckBehind,
    pub(crate) forks: ForkRejoins,
    /// Per group, when the last head read over messages that would not open
    /// was asked for, and whether it knew of a message sealed ahead.
    pub(crate) reads: BTreeMap<Vec<u8>, (i64, bool)>,
    pub(crate) probes: BTreeMap<Vec<u8>, Probe>,
    /// When the last drain that ran to the end began, as evidence.
    pub(crate) drain_mark: Option<i64>,
}

impl RecoveryBook {
    /// [`crate::Client::recovery_read_due`].
    pub(crate) fn read_due(&mut self, group_id: &[u8], sealed_ahead: bool, now_ms: i64) -> bool {
        if let Some((at, ahead)) = self.reads.get(group_id) {
            if now_ms.saturating_sub(*at) < UNOPENED_READ_EVERY_MS && (*ahead || !sealed_ahead) {
                return false;
            }
        }
        self.reads.insert(group_id.to_vec(), (now_ms, sealed_ahead));
        true
    }

    /// [`crate::Client::recovery_drain_complete`].
    pub(crate) fn drain_complete(
        &mut self,
        started_at_ms: i64,
        evidence: bool,
        now_ms: i64,
    ) -> Vec<Vec<u8>> {
        if evidence {
            self.drain_mark = Some(
                self.drain_mark
                    .map_or(started_at_ms, |mark| mark.max(started_at_ms)),
            );
        }
        let due = self.stuck.recheck_after_drain(started_at_ms);
        for group in &due {
            self.reads.insert(group.clone(), (now_ms, false));
        }
        due
    }

    /// The group's copy is gone: its readings start over. The fork backoff
    /// and the minute's read stay, as they belong to the group, not the copy.
    pub(crate) fn forget_copy(&mut self, group_id: &[u8]) {
        self.stuck.clear(group_id);
        self.probes.remove(group_id);
    }
}

impl crate::Client {
    /// BEGIN A HEAD READ of `group_id`, before the head is fetched. Answers
    /// [`RecoveryStep::ReadHead`] (fetch the head, then
    /// [`Self::recovery_judge`] it), [`RecoveryStep::Held`] (the group is
    /// held for its steward: every recovery waits, read nothing), or
    /// [`RecoveryStep::NoCopy`] (no active copy: nothing to judge).
    ///
    /// Snapshots, in this order, when the last complete drain began, the
    /// copy's epoch and its verifier, so the judge holds the head against
    /// what the copy was when the read began. A second begin before the
    /// judge replaces the snapshot. In memory only.
    pub fn recovery_begin(&mut self, group_id: &[u8]) -> crate::Result<RecoveryStep> {
        if !self.is_active(group_id).unwrap_or(false) {
            self.recovery.probes.remove(group_id);
            return Ok(RecoveryStep::NoCopy);
        }
        // A core that cannot say is "not held": the hold is a pause the
        // steward's repair ends, and a gate that failed closed would wedge
        // every group that never named a steward.
        if matches!(self.group_hold(group_id), Ok(Some(_))) {
            return Ok(RecoveryStep::Held);
        }
        let drain_mark = self.recovery.drain_mark;
        let epoch = self.epoch(group_id)?;
        let Some(verifier) = self.verifier_of_held(group_id)? else {
            return Ok(RecoveryStep::NoCopy);
        };
        self.recovery.probes.insert(
            group_id.to_vec(),
            Probe {
                epoch,
                verifier,
                drain_mark,
            },
        );
        Ok(RecoveryStep::ReadHead)
    }

    /// JUDGE A HEAD read since [`Self::recovery_begin`]: the fork check, the
    /// stuck-behind count, the lost-mailbox rule, the hold and the fork
    /// backoff, in one answer (the table in [`crate::recovery`]).
    ///
    /// `head` is the group's `ConversationHead`, or `None` when the server
    /// holds none. `fresh`: the read began after `recovery_begin` (a read by
    /// handle, or a sweep begun since); a sweep reused from before may be
    /// older than a commit the copy applied since, so a head from it below
    /// the copy answers [`RecoveryStep::ReadAgain`] and changes nothing.
    ///
    /// On the way, the head is handed to [`Self::confirm_head`] (a caller
    /// then draws any rejoin report), and for [`HeadReadKind::Check`] and
    /// [`HeadReadKind::SealedAhead`] the read is kept
    /// ([`Self::note_head_read`]) unless a fork rejoin of the group is in its
    /// backoff. A copy that moved while the head was read is judged only for
    /// being behind the head at its new epoch.
    ///
    /// On a `REJOIN_*` step the fork backoff is spent (not for
    /// `REJOIN_LOST`) and the group's readings start over: read the leaves
    /// to ask, forget the group ([`Self::forget_group`]), and send them a
    /// sealed seat ask. A group holding a saved commit answers
    /// [`RecoveryStep::SettleFirst`] instead, before any backoff is spent:
    /// settle it by the verifier logged at its epoch plus one, then read the
    /// head again. Refused with [`crate::Error::InvalidArgument`] when no
    /// `recovery_begin` came first. Under the store's write lock where it
    /// writes; flush after it (wasm).
    pub fn recovery_judge(
        &mut self,
        group_id: &[u8],
        kind: HeadReadKind,
        head: Option<&HeadReading>,
        fresh: bool,
        now_ms: i64,
    ) -> crate::Result<RecoveryStep> {
        let Some(probe) = self.recovery.probes.get(group_id).cloned() else {
            return Err(crate::Error::invalid(
                "recovery_judge needs a recovery_begin for the group first",
            ));
        };
        if !self.is_active(group_id).unwrap_or(false) {
            self.recovery.probes.remove(group_id);
            return Ok(RecoveryStep::NoCopy);
        }
        // A HEAD BELOW THE COPY from a read that may be older than it: the
        // server's head is at or past every epoch this copy reached through
        // it, so only a read begun after the snapshot can say it is below.
        if kind != HeadReadKind::Lost && !fresh && head.is_some_and(|h| h.epoch < probe.epoch) {
            return Ok(RecoveryStep::ReadAgain);
        }
        self.recovery.probes.remove(group_id);
        if let Some(head) = head.filter(|h| h.verifier.len() == 32) {
            if let Err(err) = self.confirm_head(group_id, head.epoch, &head.verifier) {
                log::warn!("peachy-mls: could not hand a head read to the copy: {err}");
            }
        }
        let current = self.epoch(group_id)?;
        let verdict = match head {
            None => HeadVerdict::Level,
            Some(h) if h.epoch > current => HeadVerdict::Behind,
            // The copy moved while the head was read: what the head says at
            // or below it was read against another epoch, and proves nothing.
            Some(_) if current != probe.epoch => HeadVerdict::Level,
            Some(h) => {
                let rolled_back = h.epoch < current
                    && h.verifier.len() == 32
                    && self
                        .head_rolled_back(group_id, h.epoch, &h.verifier)
                        .unwrap_or(false);
                let matches = (h.verifier.len() == 32)
                    .then(|| h.verifier.as_slice() == probe.verifier.as_slice());
                head_verdict(current, Some(h.epoch), matches, rolled_back)
            }
        };

        if kind == HeadReadKind::Lost {
            // The lost-mailbox rule: a copy behind the head has lost the
            // commits that would carry it up. Nothing else is judged here.
            if verdict != HeadVerdict::Behind {
                return Ok(RecoveryStep::InStep);
            }
            if self.hold_for_missing_commit(group_id) {
                return Ok(RecoveryStep::HoldEntered);
            }
            if self.has_saved_commit(group_id).unwrap_or(false) {
                return Ok(RecoveryStep::SettleFirst);
            }
            self.recovery.stuck.clear(group_id);
            return Ok(RecoveryStep::RejoinLost);
        }

        // Kept, whatever it answered, unless a fork rejoin is in its
        // backoff: nothing re-asks for a fork the backoff holds back, so the
        // next open reads again.
        if self.recovery.forks.may_rejoin(group_id, now_ms) {
            if let Err(err) = self.note_head_read(group_id, now_ms) {
                log::warn!("peachy-mls: could not keep when a head was read: {err}");
            }
        }
        let step = match verdict {
            HeadVerdict::Level => {
                self.recovery.stuck.clear(group_id);
                return Ok(RecoveryStep::InStep);
            }
            HeadVerdict::RolledBack => {
                self.recovery.stuck.clear(group_id);
                log::warn!(
                    "peachy-mls: a head below this copy is one the group's head stood above; \
                     the copy is kept"
                );
                return Ok(RecoveryStep::RolledBack);
            }
            HeadVerdict::Behind => {
                let stuck =
                    self.recovery
                        .stuck
                        .note_behind(group_id, current, now_ms, probe.drain_mark);
                if !stuck && kind != HeadReadKind::SealedAhead {
                    return Ok(RecoveryStep::Behind);
                }
                // The commit that would carry the copy up is missing: a
                // group with a steward holds and fetches it instead.
                if self.hold_for_missing_commit(group_id) {
                    return Ok(RecoveryStep::HoldEntered);
                }
                RecoveryStep::RejoinStuck
            }
            HeadVerdict::Forked => {
                self.recovery.stuck.clear(group_id);
                RecoveryStep::RejoinForked
            }
        };
        // A SAVED COMMIT would be dropped unheard by the forget: settled
        // first, by the verifier the server logged past it, so a copy whose
        // own commit the server took and another member built on is not held
        // below the head for good (its echo is never applied).
        if self.has_saved_commit(group_id).unwrap_or(false) {
            return Ok(RecoveryStep::SettleFirst);
        }
        if !self.recovery.forks.may_rejoin(group_id, now_ms) {
            log::warn!("peachy-mls: off the group's head again soon after a rejoin; waiting");
            return Ok(RecoveryStep::Backoff);
        }
        self.recovery.forks.note(group_id, now_ms);
        self.recovery.stuck.clear(group_id);
        Ok(step)
    }

    /// WHETHER TO READ THE HEAD over messages (or a commit) of `group_id`
    /// that would not open: at most once a minute per group, except that a
    /// message sealed past the copy's epoch (`sealed_ahead`, as
    /// [`crate::Error::StaleCopy`] says) is let through once when the last
    /// read did not know of one. A true answer counts as that read. In
    /// memory.
    pub fn recovery_read_due(&mut self, group_id: &[u8], sealed_ahead: bool, now_ms: i64) -> bool {
        self.recovery.read_due(group_id, sealed_ahead, now_ms)
    }

    /// A MAILBOX DRAIN THAT BEGAN AT `started_at_ms` RAN TO THE END: every
    /// page fetched, nothing held back. `evidence` is false for a drain whose
    /// first page the stream carried, read on the server before the drain
    /// began: its groups are read again, but nothing is stranded on it.
    ///
    /// Answers the groups whose last `behind` reading stranded nothing and
    /// came before this drain began, each handed out once: read each one's
    /// head now ([`HeadReadKind::Check`]). A copy truly behind has caught up
    /// by then and reads level; one this drain could not carry up is
    /// stranded. Each counts as its group's minute's read. In memory.
    pub fn recovery_drain_complete(
        &mut self,
        started_at_ms: i64,
        evidence: bool,
        now_ms: i64,
    ) -> Vec<Vec<u8>> {
        self.recovery
            .drain_complete(started_at_ms, evidence, now_ms)
    }

    /// Hold the group for its steward over a missing commit; false, and
    /// nothing done, for a group the core does not hold (every group, until
    /// a build writes stewards).
    fn hold_for_missing_commit(&mut self, group_id: &[u8]) -> bool {
        self.enter_hold(group_id, crate::steward::HoldReason::UnopenableCommit)
            .unwrap_or(false)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn steps_keep_their_numbers_and_names() {
        for (index, step) in RecoveryStep::ALL.iter().enumerate() {
            assert_eq!(step.code() as usize, index, "{}", step.name());
        }
        let names: std::collections::BTreeSet<_> =
            RecoveryStep::ALL.iter().map(|s| s.name()).collect();
        assert_eq!(names.len(), RecoveryStep::ALL.len());
        assert!(RecoveryStep::RejoinLost.rejoins());
        assert!(!RecoveryStep::Backoff.rejoins());
    }

    #[test]
    fn the_minutes_read_lets_a_message_sealed_ahead_through_once() {
        let mut book = RecoveryBook::default();
        assert!(book.read_due(b"g", false, 0));
        assert!(!book.read_due(b"g", false, 59_999));
        assert!(book.read_due(b"g", true, 30_000), "ahead is news");
        assert!(!book.read_due(b"g", true, 31_000), "and only once");
        assert!(!book.read_due(b"g", false, 32_000));
        assert!(book.read_due(b"g", false, 90_000));
        assert!(book.read_due(b"other", false, 90_000));
    }

    #[test]
    fn a_drain_owes_its_rechecks_once_and_counts_them_as_the_minutes_read() {
        let mut book = RecoveryBook::default();
        assert!(!book.stuck.note_behind(b"g", 4, 1_000, None));
        assert!(
            book.drain_complete(500, true, 600).is_empty(),
            "began before the reading"
        );
        assert_eq!(book.drain_mark, Some(500));
        assert_eq!(
            book.drain_complete(2_000, false, 2_100),
            vec![b"g".to_vec()]
        );
        assert_eq!(
            book.drain_mark,
            Some(500),
            "a drain that is no evidence moves no mark"
        );
        assert!(!book.read_due(b"g", false, 2_200));
        assert!(book.drain_complete(3_000, true, 3_100).is_empty());
        assert_eq!(book.drain_mark, Some(3_000));
    }
}
