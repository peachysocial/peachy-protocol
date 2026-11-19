// SPDX-License-Identifier: MIT
//! The ring reducer over arbitrary event sequences: `ring_step`, from idle,
//! and its JSON door `ring_step_json` beside it. docs/mls-core.md
//! §Fuzzing.
//!
//! Events are decoded from the input a few bytes at a time over small
//! alphabets (three call ids, one of them differing from another only in
//! case; two conversations; this account and two others), so sequences hit
//! the same call again and again. After every step:
//! - nothing panicked, and the JSON door gives the same step;
//! - a `ring` effect comes only from an `offer` that is not from this
//!   account, whose gate is `allowed`, that is fresh by every clock
//!   (`offer_is_fresh`: no older than `CALL_OFFER_MAX_AGE_MS`, and the
//!   caller's stamp within `CALL_OFFER_MAX_SKEW_MS` of this device's clock),
//!   and that is a 1:1 or a ringing offer in a group of at most
//!   `CALL_RING_CAP`; and the state is then ringing for it;
//! - an offer for the call this device is already on never rings again (a
//!   redelivery);
//! - a `*_elsewhere` outcome comes only from this account's own devices, and
//!   a hangup from anyone but the caller or this account never stops a ring;
//! - every `send` effect carries a signal the codec can seal;
//! - a call this step ended is not the call the new state is on.
//!
//! - a call this device already recorded as over never rings again (R-K5,
//!   N15): the harness keeps every ended call id and passes `alreadyEnded`,
//!   as a client's call history does.

#![no_main]

use std::collections::HashSet;

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::call::{
    encode_call_signal, ring_step, ring_step_json, CallMedia, CallSignal, HangupReason, RingEffect,
    RingEvent, RingGate, RingOutcome, RingState, RingStep, CALL_OFFER_MAX_AGE_MS,
    CALL_OFFER_MAX_SKEW_MS, CALL_RING_CAP,
};

const CALL_IDS: [&str; 3] = [
    "00112233445566778899aabbccddeeff",
    "ffeeddccbbaa99887766554433221100",
    "00112233445566778899AABBCCDDEEFF",
];
const CONVERSATIONS: [&str; 2] = ["conv-a", "conv-b"];
/// Index 0 is this device's own account.
const SENDERS: [&str; 3] = ["me", "alice", "bob"];
const AGES: [i64; 6] = [
    0,
    -5,
    CALL_OFFER_MAX_AGE_MS as i64,
    CALL_OFFER_MAX_AGE_MS as i64 + 1,
    i64::MAX,
    i64::MIN,
];
/// This device's clock, fixed: the caller's stamp is picked around it.
const NOW_MS: i64 = 1_789_516_800_000;
const STAMP_OFFSETS: [i64; 8] = [
    0,
    -1_500,
    CALL_OFFER_MAX_SKEW_MS as i64,
    CALL_OFFER_MAX_SKEW_MS as i64 + 1,
    -((CALL_OFFER_MAX_AGE_MS + CALL_OFFER_MAX_SKEW_MS) as i64),
    -((CALL_OFFER_MAX_AGE_MS + CALL_OFFER_MAX_SKEW_MS) as i64) - 1,
    i64::MAX,
    i64::MIN,
];
const MEMBERS: [u32; 6] = [0, 2, CALL_RING_CAP, CALL_RING_CAP + 1, 3, u32::MAX];
const REASONS: [HangupReason; 7] = [
    HangupReason::Normal,
    HangupReason::Declined,
    HangupReason::Busy,
    HangupReason::AcceptedElsewhere,
    HangupReason::DeclinedElsewhere,
    HangupReason::BusyElsewhere,
    HangupReason::NeedPermission,
];

struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn next(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
    fn pick<T: Copy>(&mut self, from: &[T]) -> Option<T> {
        Some(from[usize::from(self.next()?) % from.len()])
    }
}

fn media(b: u8) -> CallMedia {
    if b & 1 == 0 {
        CallMedia::Audio
    } else {
        CallMedia::Video
    }
}

fn event(input: &mut Bytes<'_>, ended: &HashSet<String>) -> Option<RingEvent> {
    let kind = input.next()?;
    let call_id = input.pick(&CALL_IDS)?.to_string();
    Some(match kind % 8 {
        0 => {
            let flags = input.next()?;
            let one_to_one = flags & 2 != 0;
            RingEvent::PlaceCall {
                call_id,
                conversation: input.pick(&CONVERSATIONS)?.to_string(),
                media: media(flags),
                member_count: if one_to_one { 2 } else { input.pick(&MEMBERS)? },
                one_to_one,
                now_ms: 1_789_516_800_000,
            }
        }
        1 => {
            let flags = input.next()?;
            let sender = input.next()?;
            let one_to_one = flags & 2 != 0;
            RingEvent::Offer {
                already_ended: ended.contains(&call_id),
                call_id,
                conversation: input.pick(&CONVERSATIONS)?.to_string(),
                sender: SENDERS[usize::from(sender) % 3].to_string(),
                from_self: sender % 3 == 0,
                media: media(flags),
                ring: flags & 4 != 0,
                age_ms: input.pick(&AGES)?,
                created_at_ms: NOW_MS.saturating_add(input.pick(&STAMP_OFFSETS)?),
                now_ms: NOW_MS,
                member_count: if one_to_one { 2 } else { input.pick(&MEMBERS)? },
                one_to_one,
                gate: input.pick(&[
                    RingGate::Allowed,
                    RingGate::Blocked,
                    RingGate::NeedsPermission,
                ])?,
                early_hangup: None,
            }
        }
        2 => {
            let sender = input.next()?;
            RingEvent::Answer {
                call_id,
                conversation: input.pick(&CONVERSATIONS)?.to_string(),
                sender: SENDERS[usize::from(sender) % 3].to_string(),
                from_self: sender % 3 == 0,
            }
        }
        3 => {
            let sender = input.next()?;
            RingEvent::Hangup {
                call_id,
                conversation: input.pick(&CONVERSATIONS)?.to_string(),
                sender: SENDERS[usize::from(sender) % 3].to_string(),
                from_self: sender % 3 == 0,
                reason: input.pick(&REASONS)?,
            }
        }
        4 => RingEvent::Accept,
        5 => RingEvent::Decline,
        6 => RingEvent::HangUp {
            alone: input.next()? & 1 != 0,
        },
        _ => RingEvent::Timeout { call_id },
    })
}

fn state_call_id(state: &RingState) -> Option<&str> {
    match state {
        RingState::Idle => None,
        RingState::Outgoing { call_id, .. }
        | RingState::Ringing { call_id, .. }
        | RingState::InCall { call_id, .. } => Some(call_id),
    }
}

fn check(before: &RingState, event: &RingEvent, step: &RingStep) {
    for effect in &step.effects {
        match effect {
            RingEffect::Ring { call_id, .. } => {
                let RingEvent::Offer {
                    call_id: offered,
                    from_self,
                    ring,
                    age_ms,
                    created_at_ms,
                    now_ms,
                    member_count,
                    one_to_one,
                    gate,
                    already_ended,
                    ..
                } = event
                else {
                    panic!("{event:?} rang");
                };
                assert_eq!(call_id, offered);
                assert!(!from_self, "rang for this account's own offer");
                assert!(!already_ended, "a call already over rang again");
                assert_eq!(*gate, RingGate::Allowed, "rang through a {gate:?} gate");
                assert!(
                    *age_ms <= CALL_OFFER_MAX_AGE_MS as i64,
                    "rang for a stale offer"
                );
                let stamp_age = now_ms.saturating_sub(*created_at_ms);
                assert!(
                    stamp_age >= -(CALL_OFFER_MAX_SKEW_MS as i64)
                        && stamp_age <= (CALL_OFFER_MAX_AGE_MS + CALL_OFFER_MAX_SKEW_MS) as i64,
                    "rang for an offer the caller dated {stamp_age} ms ago"
                );
                assert!(
                    *one_to_one || (*ring && *member_count <= CALL_RING_CAP),
                    "a group of {member_count} rang (ring={ring})"
                );
                assert_ne!(
                    state_call_id(before),
                    Some(call_id.as_str()),
                    "a redelivered offer rang"
                );
                assert!(
                    matches!(&step.state, RingState::Ringing { call_id: now, .. } if now == call_id),
                    "rang but the state is {:?}",
                    step.state
                );
            }
            RingEffect::Ended { call_id, outcome } => {
                if matches!(
                    outcome,
                    RingOutcome::AnsweredElsewhere
                        | RingOutcome::DeclinedElsewhere
                        | RingOutcome::BusyElsewhere
                ) {
                    let own = matches!(
                        event,
                        RingEvent::Hangup {
                            from_self: true,
                            ..
                        } | RingEvent::Answer {
                            from_self: true,
                            ..
                        }
                    );
                    assert!(own, "{outcome:?} from {event:?}");
                }
                assert_ne!(
                    state_call_id(&step.state),
                    Some(call_id.as_str()),
                    "ended {call_id} but still on it"
                );
            }
            RingEffect::Send { signal, .. } => {
                let signal = CallSignal::try_from(signal).expect("a sent signal converts");
                encode_call_signal(&signal).expect("a sent signal encodes");
            }
            _ => {}
        }
    }
    // A hangup from a stranger never stops a ring.
    if let (
        RingState::Ringing {
            call_id, caller, ..
        },
        RingEvent::Hangup {
            call_id: hung,
            sender,
            from_self: false,
            ..
        },
    ) = (before, event)
    {
        if call_id == hung && sender != caller {
            assert_eq!(&step.state, before, "{sender} stopped {caller}'s ring");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Bytes(data);
    let mut state = RingState::Idle;
    let mut ended: HashSet<String> = HashSet::new();
    let mut steps = 0;
    while let Some(event) = event(&mut input, &ended) {
        let step = ring_step(&state, &event);
        check(&state, &event, &step);

        // The JSON door agrees with the Rust one.
        let state_json = serde_json::to_string(&state).expect("state prints");
        let event_json = serde_json::to_string(&event).expect("event prints");
        let out = ring_step_json(&state_json, &event_json).expect("the JSON door steps");
        let via_json: RingStep = serde_json::from_str(&out).expect("the step parses");
        assert_eq!(via_json, step);

        for effect in &step.effects {
            if let RingEffect::Ended { call_id, .. } = effect {
                ended.insert(call_id.clone());
            }
        }
        state = step.state;
        steps += 1;
        if steps > 256 {
            break;
        }
    }
});
