// SPDX-License-Identifier: MIT
//! THE RECOVERY DRIVER (`peachy_mls_core::recovery`,
//! docs/delivery.md §A commit the server refuses): a copy that fell
//! behind or forked is told to rejoin by the core, the same way on every
//! client.
//!
//! Two halves. The rules are replayed from the published table of the
//! apps' fixture (`mls/fixtures/formats/commit-refusal.json`), so the core's
//! decisions are the apps', case for case. Then the driver itself, on real
//! copies: in step, behind and stuck, a message sealed past the copy
//! (`StaleCopy`), forked at the same epoch, forked ahead, a stale sweep, the
//! lost-mailbox rule and the fork backoff.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::recovery::{
    commit_was_taken, fork_rejoin_delay_ms, head_verdict, refusal_worth_checking, ForkRejoins,
    HeadVerdict, StuckBehind, CHECKED_REFUSAL_CODES, FORK_REJOIN_CAP_MS, FORK_REJOIN_FIRST_MS,
    STUCK_BEHIND_CHECKS, STUCK_BEHIND_MS, STUCK_BEHIND_WINDOW_MS,
};
use peachy_mls_core::{Client, Error, HeadReadKind, HeadReading, RecoveryStep};
use serde_json::Value;
use support::{client, head_of, issuer};

const G: &[u8] = b"9e1a7c22-4b3d-4f6e-8a1b-2c3d4e5f6a7b";

fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/formats/commit-refusal.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn opt_u64(v: &Value) -> Option<u64> {
    v.as_u64()
}

fn opt_bool(v: &Value) -> Option<bool> {
    v.as_bool()
}

#[test]
fn the_rules_replay_the_apps_fixture() {
    let f = fixture();
    let codes: Vec<&str> = f["checkedCodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert_eq!(codes, CHECKED_REFUSAL_CODES.to_vec());
    assert_eq!(f["forkRejoinFirstMs"].as_i64(), Some(FORK_REJOIN_FIRST_MS));
    assert_eq!(f["forkRejoinCapMs"].as_i64(), Some(FORK_REJOIN_CAP_MS));
    assert_eq!(f["stuckBehindMs"].as_i64(), Some(STUCK_BEHIND_MS));
    assert_eq!(
        f["stuckBehindChecks"].as_u64(),
        Some(u64::from(STUCK_BEHIND_CHECKS))
    );
    assert_eq!(
        f["stuckBehindWindowMs"].as_i64(),
        Some(STUCK_BEHIND_WINDOW_MS)
    );

    let verdicts = f["verdicts"].as_array().unwrap();
    assert!(verdicts.len() >= 10);
    for c in verdicts {
        let name = c["name"].as_str().unwrap();
        let got = if refusal_worth_checking(c["code"].as_str().unwrap()) {
            match head_verdict(
                c["localEpoch"].as_u64().unwrap(),
                opt_u64(&c["headEpoch"]),
                opt_bool(&c["verifierMatches"]),
                c["headPassedThrough"].as_bool().unwrap_or(false),
            ) {
                HeadVerdict::Level => "retry",
                HeadVerdict::Behind => "behind",
                HeadVerdict::Forked => "forked",
                HeadVerdict::RolledBack => "rolledBack",
            }
        } else {
            "retry"
        };
        assert_eq!(got, c["verdict"].as_str().unwrap(), "{name}");
    }

    for c in f["forkRejoinDelays"].as_array().unwrap() {
        assert_eq!(
            fork_rejoin_delay_ms(c["rejoins"].as_u64().unwrap() as u32),
            c["delayMs"].as_i64().unwrap()
        );
    }
    for c in f["forkRejoins"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let mut rejoins = ForkRejoins::default();
        for e in c["events"].as_array().unwrap() {
            if let Some(at) = e["checkAt"].as_i64() {
                assert_eq!(
                    rejoins.may_rejoin(b"g", at),
                    e["may"].as_bool().unwrap(),
                    "{name} at {at}"
                );
            } else {
                rejoins.note(b"g", e["rejoinedAt"].as_i64().unwrap());
            }
        }
        assert!(rejoins.may_rejoin(b"other", 0), "{name}");
    }

    for c in f["commitsTaken"].as_array().unwrap() {
        assert_eq!(
            commit_was_taken(
                c["commitEpoch"].as_u64().unwrap(),
                opt_u64(&c["headEpoch"]),
                opt_bool(&c["headVerifierIsNext"]),
                opt_bool(&c["loggedVerifierIsNext"]),
            ),
            c["taken"].as_bool().unwrap(),
            "{}",
            c["name"].as_str().unwrap()
        );
    }

    let runs = f["stuckBehind"].as_array().unwrap();
    assert!(runs.len() >= 17);
    for c in runs {
        let name = c["name"].as_str().unwrap();
        let mut stuck = StuckBehind::default();
        for e in c["events"].as_array().unwrap() {
            if e["clear"].as_bool() == Some(true) {
                stuck.clear(b"g");
            } else if let Some(started) = e["drainCompleteStartedAtMs"].as_i64() {
                let want: Vec<Vec<u8>> = if e["recheck"].as_bool().unwrap() {
                    vec![b"g".to_vec()]
                } else {
                    vec![]
                };
                assert_eq!(
                    stuck.recheck_after_drain(started),
                    want,
                    "{name}: {started}"
                );
            } else {
                assert_eq!(
                    stuck.note_behind(
                        b"g",
                        e["localEpoch"].as_u64().unwrap(),
                        e["atMs"].as_i64().unwrap(),
                        e["lastDrainStartedAtMs"].as_i64(),
                    ),
                    e["stuck"].as_bool().unwrap(),
                    "{name} at {}",
                    e["atMs"]
                );
            }
        }
        assert!(!stuck.note_behind(b"other", 4, 10_000_000, None), "{name}");
    }
}

// ---- The driver, on real copies --------------------------------------------

/// Ada founds G and seats Bo at the head.
fn pair() -> (Client, Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    ada.create_group(G).unwrap();
    let add = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    let head = head_of(&ada, G);
    bo.join_from_welcome_at_head(&add.welcome.unwrap(), head.0, &head.1)
        .unwrap();
    (ada, bo)
}

/// The group's head where `who`'s copy stands.
fn head(who: &Client) -> HeadReading {
    let (epoch, verifier) = head_of(who, G);
    HeadReading {
        epoch,
        verifier: verifier.to_vec(),
    }
}

/// Ada commits; Bo never hears of it. Answers the commit.
fn ada_moves_on(ada: &mut Client) -> Vec<u8> {
    let bundle = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bundle.commit
}

fn judge(
    bo: &mut Client,
    kind: HeadReadKind,
    head: Option<&HeadReading>,
    now: i64,
) -> RecoveryStep {
    assert_eq!(bo.recovery_begin(G).unwrap(), RecoveryStep::ReadHead);
    bo.recovery_judge(G, kind, head, true, now).unwrap()
}

#[test]
fn a_copy_at_the_head_is_in_step() {
    let (_ada, mut bo) = pair();
    let level = head(&bo);
    assert_eq!(
        judge(&mut bo, HeadReadKind::Check, Some(&level), 1_000),
        RecoveryStep::InStep
    );
    assert_eq!(
        bo.last_head_read(G).unwrap(),
        Some(1_000),
        "the read is kept"
    );
    assert_eq!(
        judge(&mut bo, HeadReadKind::Check, None, 2_000),
        RecoveryStep::InStep,
        "no head"
    );
    let blank = HeadReading {
        epoch: level.epoch,
        verifier: vec![],
    };
    assert_eq!(
        judge(&mut bo, HeadReadKind::Check, Some(&blank), 3_000),
        RecoveryStep::InStep,
        "no verifier proves nothing"
    );
}

/// THE BOT IN THE REVIEW: one commit missed, and from then on every message
/// says only "epoch differs". Now the message door says what it means, and
/// the head read that follows says to rejoin.
#[test]
fn a_message_sealed_past_the_copy_is_a_stale_copy_and_the_head_says_rejoin() {
    let (mut ada, mut bo) = pair();
    let missed = ada_moves_on(&mut ada);
    let message = ada.encrypt(G, b"your turn").unwrap();
    let copy = bo.epoch(G).unwrap();
    match bo.process_message(G, &message) {
        Err(Error::StaleCopy {
            message_epoch,
            copy_epoch,
        }) => {
            assert_eq!(copy_epoch, copy);
            assert_eq!(message_epoch, copy + 1);
        }
        other => panic!("expected StaleCopy, got {other:?}"),
    }
    assert_eq!(
        Error::StaleCopy {
            message_epoch: 2,
            copy_epoch: 1
        }
        .code(),
        23
    );

    assert!(bo.recovery_read_due(G, true, 1_000));
    assert!(!bo.recovery_read_due(G, true, 1_001), "once a minute");
    let ahead = head(&ada);
    assert_eq!(
        judge(&mut bo, HeadReadKind::SealedAhead, Some(&ahead), 1_000),
        RecoveryStep::RejoinStuck
    );
    // The commit it missed still applies: the driver only advises.
    assert_eq!(bo.epoch(G).unwrap(), copy);
    bo.process_commit(G, &missed).unwrap();
    assert_eq!(bo.epoch(G).unwrap(), copy + 1);
}

#[test]
fn behind_is_caught_up_until_a_whole_drain_leaves_it_where_it_was() {
    let (mut ada, mut bo) = pair();
    ada_moves_on(&mut ada);
    let ahead = head(&ada);
    // A race: the commit is in the mailbox.
    assert_eq!(
        judge(&mut bo, HeadReadKind::Check, Some(&ahead), 1_000),
        RecoveryStep::Behind
    );
    // A drain that began before that reading proves nothing and owes nothing.
    assert!(bo.recovery_drain_complete(500, true, 1_100).is_empty());
    // One that began after it owes the second reading...
    assert_eq!(
        bo.recovery_drain_complete(1_500, true, 2_000),
        vec![G.to_vec()]
    );
    // ...counted as the minute's read...
    assert!(!bo.recovery_read_due(G, false, 2_001));
    // ...and still behind at the same epoch after it, the copy is stranded.
    assert_eq!(
        judge(&mut bo, HeadReadKind::Check, Some(&ahead), 2_100),
        RecoveryStep::RejoinStuck
    );
}

#[test]
fn behind_with_no_drain_strands_on_the_clock_rule() {
    let (mut ada, mut bo) = pair();
    ada_moves_on(&mut ada);
    let ahead = head(&ada);
    assert_eq!(
        judge(&mut bo, HeadReadKind::Check, Some(&ahead), 0),
        RecoveryStep::Behind
    );
    assert_eq!(
        judge(&mut bo, HeadReadKind::Check, Some(&ahead), 60_000),
        RecoveryStep::Behind
    );
    assert_eq!(
        judge(&mut bo, HeadReadKind::Check, Some(&ahead), 300_000),
        RecoveryStep::RejoinStuck
    );
}

/// THE FORK THE SDK MISSED: the same epoch as the head, on another branch.
/// Only the verifier tells, and the driver compares it.
#[test]
fn the_same_epoch_on_another_branch_is_a_fork() {
    let (mut ada, mut bo) = pair();
    // Bo merges a commit of his own the server never took (a lost race he
    // took for a win); Ada's commit at the same epoch is the head.
    bo.self_update(G).unwrap();
    bo.merge_pending_commit(G).unwrap();
    ada_moves_on(&mut ada);
    let theirs = head(&ada);
    assert_eq!(theirs.epoch, bo.epoch(G).unwrap(), "same epoch");
    assert_ne!(theirs, head(&bo), "other branch");
    assert_eq!(
        judge(&mut bo, HeadReadKind::Check, Some(&theirs), 1_000),
        RecoveryStep::RejoinForked
    );
    // A second fork soon after waits out the backoff, and keeps no read.
    assert_eq!(
        judge(&mut bo, HeadReadKind::Check, Some(&theirs), 2_000),
        RecoveryStep::Backoff
    );
    assert_eq!(bo.last_head_read(G).unwrap(), Some(1_000));
    assert_eq!(
        judge(&mut bo, HeadReadKind::Check, Some(&theirs), 1_000 + 600_000),
        RecoveryStep::RejoinForked
    );
    // The lost-mailbox rule judges only behind.
    assert_eq!(
        judge(&mut bo, HeadReadKind::Lost, Some(&theirs), 10_000_000),
        RecoveryStep::InStep
    );
}

#[test]
fn a_head_below_the_copy_is_read_fresh_before_it_is_a_fork() {
    let (mut ada, mut bo) = pair();
    let below = head(&ada);
    // Bo applied a commit the server never took (placed for him, refused at
    // the head): he is ahead of it, on a branch nobody else holds.
    let stray = ada.self_update(G).unwrap();
    ada.clear_pending_commit(G).unwrap();
    bo.process_commit(G, &stray.commit).unwrap();
    assert_eq!(bo.epoch(G).unwrap(), below.epoch + 1);
    assert_eq!(bo.recovery_begin(G).unwrap(), RecoveryStep::ReadHead);
    // A sweep from before the begin may simply be older than the copy.
    assert_eq!(
        bo.recovery_judge(G, HeadReadKind::Check, Some(&below), false, 1_000)
            .unwrap(),
        RecoveryStep::ReadAgain
    );
    // The snapshot stands; a fresh read says the same, and it is a fork.
    assert_eq!(
        bo.recovery_judge(G, HeadReadKind::Check, Some(&below), true, 1_100)
            .unwrap(),
        RecoveryStep::RejoinForked
    );
}

#[test]
fn a_lost_mailbox_rejoins_a_copy_behind_at_once() {
    let (mut ada, mut bo) = pair();
    let level = head(&bo);
    assert_eq!(
        judge(&mut bo, HeadReadKind::Lost, Some(&level), 0),
        RecoveryStep::InStep
    );
    assert_eq!(
        judge(&mut bo, HeadReadKind::Lost, None, 0),
        RecoveryStep::InStep
    );
    ada_moves_on(&mut ada);
    assert_eq!(
        judge(&mut bo, HeadReadKind::Lost, Some(&head(&ada)), 0),
        RecoveryStep::RejoinLost
    );
    assert_eq!(
        bo.last_head_read(G).unwrap(),
        None,
        "a lost-mailbox read is not the open's"
    );
}

#[test]
fn the_judge_needs_its_begin_and_a_forgotten_copy_has_nothing_to_judge() {
    let (mut ada, mut bo) = pair();
    let level = head(&bo);
    assert!(matches!(
        bo.recovery_judge(G, HeadReadKind::Check, Some(&level), true, 0),
        Err(Error::InvalidArgument(_))
    ));
    assert_eq!(
        bo.recovery_begin(b"no-such-group").unwrap(),
        RecoveryStep::NoCopy
    );

    // A behind reading, then the copy is forgotten: its count starts over.
    ada_moves_on(&mut ada);
    let ahead = head(&ada);
    assert_eq!(
        judge(&mut bo, HeadReadKind::Check, Some(&ahead), 0),
        RecoveryStep::Behind
    );
    assert_eq!(bo.recovery_begin(G).unwrap(), RecoveryStep::ReadHead);
    bo.forget_group(G).unwrap();
    assert_eq!(bo.recovery_begin(G).unwrap(), RecoveryStep::NoCopy);
    assert!(
        bo.recovery_drain_complete(10, true, 10).is_empty(),
        "a forgotten copy is owed no second reading"
    );
}

#[test]
fn a_copy_that_moved_while_the_head_was_read_is_judged_only_for_behind() {
    let (mut ada, mut bo) = pair();
    let bundle = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let ahead = head(&ada);
    assert_eq!(bo.recovery_begin(G).unwrap(), RecoveryStep::ReadHead);
    // The drain applies the commit while the head is in flight.
    bo.process_commit(G, &bundle.commit).unwrap();
    assert_eq!(
        bo.recovery_judge(G, HeadReadKind::Check, Some(&ahead), true, 0)
            .unwrap(),
        RecoveryStep::InStep
    );
}

/// THE SAVED COMMIT A REJOIN WOULD DROP: Ada staged a commit, the process
/// went, the server took it and Bo built on it. Her copy stays below the head
/// (her own echo is never applied), and forgetting it would drop the commit
/// unheard, so the driver answers SETTLE_FIRST, spending no backoff, until it
/// is settled by the verifier the server logged past it.
#[test]
fn a_rejoin_over_a_saved_commit_settles_it_first() {
    use peachy_mls_core::{PeachyStorage, SavedCommit, SqliteKv};
    let path = std::env::temp_dir().join(format!(
        "peachy-recovery-saved-{}.sqlite",
        std::process::id()
    ));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    let store = || PeachyStorage::open(Box::new(SqliteKv::open(&path).unwrap())).unwrap();
    let server = issuer();
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let commit = {
        let mut ada = support::client_on(&server, 1, "actor-ada", "device-ada", store());
        ada.create_group(G).unwrap();
        let add = ada
            .add_member(G, &bo.generate_key_package().unwrap())
            .unwrap();
        ada.merge_pending_commit(G).unwrap();
        let at = head_of(&ada, G);
        bo.join_from_welcome_at_head(&add.welcome.unwrap(), at.0, &at.1)
            .unwrap();
        // Staged and flushed; the answer never comes back to this run.
        ada.self_update(G).unwrap().commit
    };
    let mut ada = support::client_on(&server, 1, "actor-ada", "device-ada", store());
    assert!(ada.has_saved_commit(G).unwrap(), "the open kept the stage");
    let saved_at = ada.epoch(G).unwrap();
    // The server took it; Bo applied it and built on it.
    bo.process_commit(G, &commit).unwrap();
    let logged = head(&bo);
    assert_eq!(logged.epoch, saved_at + 1);
    bo.self_update(G).unwrap();
    bo.merge_pending_commit(G).unwrap();
    let past = head(&bo);
    assert_eq!(
        ada.settle_saved_commit(G, past.epoch, &past.verifier)
            .unwrap(),
        SavedCommit::Waiting,
        "the head alone cannot say"
    );

    let message = bo.encrypt(G, b"still there?").unwrap();
    assert!(matches!(
        ada.process_message(G, &message),
        Err(Error::StaleCopy { .. })
    ));
    assert_eq!(
        judge(&mut ada, HeadReadKind::SealedAhead, Some(&past), 1_000),
        RecoveryStep::SettleFirst
    );
    assert_eq!(
        judge(&mut ada, HeadReadKind::Lost, Some(&past), 1_100),
        RecoveryStep::SettleFirst
    );
    // FetchVerifierAt(handle, saved_at + 1) is the commit's: merged.
    assert_eq!(
        ada.settle_saved_commit(G, logged.epoch, &logged.verifier)
            .unwrap(),
        SavedCommit::Merged
    );
    assert!(!ada.has_saved_commit(G).unwrap());
    // Still behind (Bo's later commit never reached her here), and now free
    // to rejoin; no backoff was spent on the settle.
    assert_eq!(
        judge(&mut ada, HeadReadKind::SealedAhead, Some(&past), 1_200),
        RecoveryStep::RejoinStuck
    );
    drop(ada);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
