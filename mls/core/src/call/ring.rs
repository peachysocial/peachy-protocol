// SPDX-License-Identifier: MIT
//! The ring-state reducer: one device's view of ringing and hanging up
//! (docs/calls.md §Ringing: ringing and non-ringing group calls, the ring
//! cap of 16, answered, declined or busy elsewhere on a person's other
//! devices, and busy handling).
//!
//! A pure function from `(state, event)` to `(state, effects)`. It holds no
//! clock and no timer, sends nothing and draws nothing: the client feeds it
//! what happened (a signal opened from the mailbox, a tap, a timer firing)
//! and does what the effects say (ring, stop ringing, seal and send a signal
//! to whom, join, leave, record an outcome for the call history). Four
//! clients reach one set of decisions because there is one implementation,
//! and `mls/fixtures/calls.json` pins it case by case.
//!
//! ## The behavior
//!
//! A group call and a 1:1 call share this reducer and differ only where
//! noted. It does not know how a call's media flows (a group call's media
//! server, or a direct 1:1 call's peer connection): `join` and `leave` are
//! the client's to carry out.
//!
//! - **One call at a time per device.** An offer for another call while this
//!   device is ringing, calling or in a call is BUSY, and is recorded as
//!   missed. In a 1:1 one `busy` goes to the conversation: the caller hears
//!   it, and this account's other devices read it as busy elsewhere. For a
//!   group ring `busy_elsewhere` goes to this account's own devices only, so
//!   they stop ringing; the caller hears nothing.
//! - **Stale offers do not ring.** An offer is fresh only by both clocks a
//!   device has: its `ageMs` (the server's clock for a drained offer, this
//!   device's for one off the stream) is at most 60 s, and the caller's own
//!   `createdAtMs` is within 60 s plus a 120 s skew of this device's clock,
//!   and no more than that skew ahead of it. Anything else is recorded as
//!   missed and nothing rings, so neither the server holding an offer nor a
//!   caller dating one ahead can make a phone ring for a call long over.
//! - **A group above 16 does not ring**: the offer is a notice. So is an offer
//!   that says `ring: false` — a non-ringing group-call "join" notice.
//! - **This account's own devices never ring for it**: an offer from another
//!   of my devices is ignored.
//! - **A call already over never rings again**: an offer the client marks
//!   `alreadyEnded` (its call history holds the call id) is ignored, and so is
//!   the same offer redelivered while this device is on that call.
//! - **Blocked callers ring nothing and hear nothing back.** A caller with an
//!   unaccepted message request is told `need_permission` in a 1:1 (which the
//!   caller shows as "must accept your message request") and nothing rings
//!   here.
//! - **Answered, declined or busy elsewhere.** In a 1:1 every reply goes to
//!   the whole conversation, the replier's own devices included, so a reply
//!   is addressed exactly as a message is
//!   (`docs/calls.md` §The ring is a message): accepting sends one
//!   `answer`, declining one `declined`, busy one `busy`, and my other devices
//!   read my own `answer`, `declined` or `busy` as answered, declined or busy
//!   elsewhere. A group ring's caller learns nothing from a reply: there the
//!   `*_elsewhere` hangups go to my own devices only. A ringing device that
//!   hears any of these from my own account stops and records which.
//! - **The caller cancelling** (any hangup from the caller while ringing)
//!   stops the ring and records it missed; another member's hangup leaves a
//!   group ring as it was. A group caller who hangs up while still alone in
//!   the call (the client says so in `HangUp { alone }`) sends that hangup,
//!   so nobody keeps ringing into an empty room. Once anyone joined, its
//!   leaving is just leaving.
//! - **A hangup that beats its offer.** A hangup for a call this device is not
//!   on yields `rememberHangup`; the client keeps it and passes it back as
//!   that call's offer's `earlyHangup`. If the offer would ring, the kept
//!   hangup ends it as a hangup arriving during the ring would — the caller's
//!   as missed, my own device's answer, decline or busy as that elsewhere —
//!   before the age check and without ringing. Any other kept hangup is
//!   ignored.
//! - **Ring timeout, 60 s**: a ringing device records
//!   missed; a 1:1 caller cancels the ring with `normal` and records no
//!   answer. A group caller is already in the call and does not time out.
//! - **A 1:1 caller hears busy, declined and need_permission** and ends with
//!   that outcome; a group caller ignores them.
//! - **Glare** — two people in one 1:1 calling each other at once — is broken
//!   by comparing call ids: the larger keeps its call (the other offer is
//!   ignored), the smaller ends its own with `normal` and rings for the
//!   other. Equal ids lose both.
//! - **Re-call**: an offer from the other person in a 1:1 this device is
//!   already in ends the stale call without a hangup and rings the new one.
//! - **Hanging up a 1:1 ends it for both** (`normal` to the conversation);
//!   leaving a group call is just leaving (the client sends `Left` on the
//!   live lane), and another member's hangup does not end it.
//!
//! An event about a call this device is not on (a stale timer, a late
//! answer) changes nothing, beyond a hangup being handed back to keep.
//!
//! ## The JSON forms
//!
//! [`ring_step_json`] is the door the bindings use: a state and an event in,
//! `{"state":…,"effects":[…]}` out. A `send` effect carries a complete signal
//! in [`super::CallSignalJson`] form, ready for the client's seal door, and a
//! `to` naming the recipients: `conversation` (every member device, this
//! account's other devices included) or `ownDevices` (this account's other
//! devices only).

use serde::{Deserialize, Serialize};

use super::signal::{CallMedia, CallSignalBodyJson, CallSignalJson, HangupReason};
use super::CALL_SIGNAL_VERSION;
use crate::error::{Error, Result};

/// The largest group whose call rings: above it an offer is a notice.
pub const CALL_RING_CAP: u32 = 16;
/// How long a device rings, and a 1:1 caller waits, before giving up.
pub const CALL_RING_TIMEOUT_MS: u64 = 60_000;
/// An offer older than this does not ring.
pub const CALL_OFFER_MAX_AGE_MS: u64 = 60_000;
/// How far the caller's clock (an offer's `created_at_ms`) may be from this
/// device's, either way, for the offer to ring. The server's clock alone
/// cannot keep an offer fresh past [`CALL_OFFER_MAX_AGE_MS`] plus this.
pub const CALL_OFFER_MAX_SKEW_MS: u64 = 120_000;

/// Whether an offer is fresh enough to ring, by every clock this device has:
/// `age_ms` (the server's `server_time - received_at` for a drained offer,
/// else this device's now less `created_at_ms`), and the caller's own stamp
/// against this device's clock, allowing [`CALL_OFFER_MAX_SKEW_MS`] either
/// way.
pub fn offer_is_fresh(age_ms: i64, created_at_ms: i64, now_ms: i64) -> bool {
    let max_age = CALL_OFFER_MAX_AGE_MS as i64;
    let skew = CALL_OFFER_MAX_SKEW_MS as i64;
    let stamp_age = now_ms.saturating_sub(created_at_ms);
    (-skew..=max_age).contains(&age_ms) && (-skew..=max_age + skew).contains(&stamp_age)
}

/// Whether a call in a conversation of `member_count` people rings, or is a
/// notice. The caller sets `ring` from this; the receiver applies it again.
pub fn should_ring(member_count: u32) -> bool {
    member_count <= CALL_RING_CAP
}

/// What this device is doing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "phase", rename_all = "camelCase")]
pub enum RingState {
    /// No call.
    #[default]
    Idle,
    /// This device placed a 1:1 call and is waiting for an answer. (A group
    /// caller goes straight to [`RingState::InCall`].)
    #[serde(rename_all = "camelCase")]
    Outgoing {
        call_id: String,
        conversation: String,
        media: CallMedia,
    },
    /// This device is ringing.
    #[serde(rename_all = "camelCase")]
    Ringing {
        call_id: String,
        conversation: String,
        media: CallMedia,
        /// The account that rang.
        caller: String,
        one_to_one: bool,
    },
    /// This device is in the call.
    #[serde(rename_all = "camelCase")]
    InCall {
        call_id: String,
        conversation: String,
        media: CallMedia,
        one_to_one: bool,
        /// This device placed a group call that rang the conversation. If it
        /// hangs up while still alone in the call, the ring is cancelled.
        #[serde(default, skip_serializing_if = "is_false")]
        rang: bool,
    },
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl RingState {
    fn call_id(&self) -> Option<&str> {
        match self {
            RingState::Idle => None,
            RingState::Outgoing { call_id, .. }
            | RingState::Ringing { call_id, .. }
            | RingState::InCall { call_id, .. } => Some(call_id),
        }
    }
}

/// Whether a caller may ring this device at all, as the device's own records
/// say (blocks and message requests live in the account store, so the client
/// decides this and the reducer applies it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum RingGate {
    #[default]
    Allowed,
    Blocked,
    NeedsPermission,
}

/// Something that happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RingEvent {
    /// The person starts a call from this device.
    #[serde(rename_all = "camelCase")]
    PlaceCall {
        call_id: String,
        conversation: String,
        media: CallMedia,
        /// People in the conversation, this person included.
        member_count: u32,
        one_to_one: bool,
        now_ms: i64,
    },
    /// An `Offer` arrived.
    #[serde(rename_all = "camelCase")]
    Offer {
        call_id: String,
        conversation: String,
        /// The account that sent it.
        sender: String,
        /// Whether `sender` is this device's own account.
        from_self: bool,
        media: CallMedia,
        ring: bool,
        /// How old the offer is: for one drained from the mailbox, the
        /// server's `server_time - received_at`; for one off the stream, this
        /// device's now minus `created_at_ms`.
        age_ms: i64,
        /// The offer's own `created_at_ms`, the caller's clock.
        created_at_ms: i64,
        /// This device's clock, in milliseconds, when the offer is stepped.
        now_ms: i64,
        member_count: u32,
        one_to_one: bool,
        #[serde(default)]
        gate: RingGate,
        /// This device already recorded this call as over (its call history
        /// holds `callId`). A redelivered or replayed offer for it never
        /// rings again.
        #[serde(default)]
        already_ended: bool,
        /// A Hangup for this call that arrived before this Offer did, as the
        /// client kept it from a [`RingEffect::RememberHangup`]. A caller's
        /// cancel or this account's answer elsewhere that beat the Offer
        /// means the Offer never rings.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        early_hangup: Option<EarlyHangup>,
    },
    /// An `Answer` arrived, in `conversation`. A 1:1 call takes one only
    /// from its own conversation, whose only other account is the peer.
    #[serde(rename_all = "camelCase")]
    Answer {
        call_id: String,
        conversation: String,
        sender: String,
        from_self: bool,
    },
    /// A `Hangup` arrived, in `conversation`. A 1:1 call takes one from
    /// another account only from its own conversation.
    #[serde(rename_all = "camelCase")]
    Hangup {
        call_id: String,
        conversation: String,
        sender: String,
        from_self: bool,
        reason: HangupReason,
    },
    /// The person accepted the ringing call.
    Accept,
    /// The person declined the ringing call.
    Decline,
    /// The person hung up (or cancelled an outgoing call). `alone`: nobody
    /// else is in the call this device is in (the client's participant view).
    /// A group caller who hangs up alone cancels the ring it sent.
    #[serde(rename_all = "camelCase")]
    HangUp {
        #[serde(default)]
        alone: bool,
    },
    /// The ring timer this reducer asked for fired.
    #[serde(rename_all = "camelCase")]
    Timeout { call_id: String },
}

/// Who a `send` effect goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RingTarget {
    /// Every member device of the conversation. Every 1:1 reply goes here:
    /// no 1:1 call signal is addressed differently from a message.
    Conversation,
    /// This account's other devices: a group ring's `*_elsewhere` only.
    OwnDevices,
}

/// How a call ended for this device: what the call history records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RingOutcome {
    /// Rang here and nobody answered here (cancelled, timed out, stale, or
    /// arrived while busy).
    Missed,
    /// Declined on this device.
    Declined,
    AnsweredElsewhere,
    DeclinedElsewhere,
    BusyElsewhere,
    /// A 1:1 call this device placed: the other side was busy.
    RemoteBusy,
    /// A 1:1 call this device placed: the other side declined.
    RemoteDeclined,
    /// A 1:1 call this device placed: the other side has not accepted the
    /// message request.
    NeedsPermission,
    /// A 1:1 call this device placed: nobody answered in time.
    NoAnswer,
    /// A 1:1 call this device placed: cancelled before an answer.
    Cancelled,
    /// A call this device was in, over.
    Completed,
    /// A 1:1 call this device placed lost a glare to the other side's.
    Glare,
}

/// What the client must do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RingEffect {
    /// Ring: CallKit, ConnectionService, the ringing window, the in-tab ring.
    #[serde(rename_all = "camelCase")]
    Ring {
        call_id: String,
        media: CallMedia,
        caller: String,
    },
    /// Stop ringing.
    #[serde(rename_all = "camelCase")]
    StopRinging { call_id: String },
    /// Show that a call started without ringing (a group above the cap, or
    /// a non-ringing offer).
    #[serde(rename_all = "camelCase")]
    Notice {
        call_id: String,
        media: CallMedia,
        caller: String,
    },
    /// Seal `signal` and send it to `to`.
    Send {
        to: RingTarget,
        signal: CallSignalJson,
    },
    /// Join the call: a group call's media room (which the caller creates),
    /// or a direct 1:1 call's peer connection.
    #[serde(rename_all = "camelCase")]
    Join { call_id: String },
    /// Leave the call.
    #[serde(rename_all = "camelCase")]
    Leave { call_id: String },
    /// Fire a `timeout` event for `callId` after `afterMs`.
    #[serde(rename_all = "camelCase")]
    ArmTimeout { call_id: String, after_ms: u64 },
    /// The other side of a 1:1 call this device placed answered.
    #[serde(rename_all = "camelCase")]
    PeerAnswered { call_id: String },
    /// This call is over for this device; record it.
    #[serde(rename_all = "camelCase")]
    Ended {
        call_id: String,
        outcome: RingOutcome,
    },
    /// The person cannot place a call now: this device is already on one.
    #[serde(rename_all = "camelCase")]
    Refused { call_id: String },
    /// A Hangup for a call this device is not on: keep it (by call id, a
    /// couple of minutes, a few dozen at most) and hand it back as the
    /// Offer's `earlyHangup` if that call's Offer arrives later, so a call
    /// already over never rings. Signals can arrive out of order: a drain
    /// and the live lane, a relayed ring and the app's own drain.
    #[serde(rename_all = "camelCase")]
    RememberHangup {
        call_id: String,
        hangup: EarlyHangup,
    },
}

/// A Hangup kept for a call whose Offer had not arrived
/// ([`RingEffect::RememberHangup`], [`RingEvent::Offer`]'s `early_hangup`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EarlyHangup {
    pub sender: String,
    pub from_self: bool,
    pub reason: HangupReason,
}

/// How a ringing call ends on a Hangup: the caller's (any reason) is a missed
/// call; this account's own device's answer, decline or busy is that, here.
/// Anything else (another member's, a plain hangup from my own device) does
/// not end the ring. The same rule for a Hangup that arrives while it rings
/// and for one that beat its Offer here.
fn ring_ended_by(
    caller: &str,
    sender: &str,
    from_self: bool,
    reason: HangupReason,
) -> Option<RingOutcome> {
    if from_self {
        // A 1:1 reply reaches my other devices as itself; a group ring's as
        // its `*_elsewhere`.
        match reason {
            HangupReason::AcceptedElsewhere => Some(RingOutcome::AnsweredElsewhere),
            HangupReason::DeclinedElsewhere | HangupReason::Declined => {
                Some(RingOutcome::DeclinedElsewhere)
            }
            HangupReason::BusyElsewhere | HangupReason::Busy => Some(RingOutcome::BusyElsewhere),
            _ => None,
        }
    } else if sender == caller {
        Some(RingOutcome::Missed)
    } else {
        None
    }
}

/// A reducer step's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingStep {
    pub state: RingState,
    pub effects: Vec<RingEffect>,
}

fn signal(call_id: &str, body: CallSignalBodyJson) -> CallSignalJson {
    CallSignalJson {
        version: CALL_SIGNAL_VERSION,
        call_id: call_id.to_string(),
        body,
    }
}

fn hangup(to: RingTarget, call_id: &str, reason: HangupReason) -> RingEffect {
    RingEffect::Send {
        to,
        signal: signal(call_id, CallSignalBodyJson::Hangup { reason }),
    }
}

fn ended(call_id: &str, outcome: RingOutcome) -> RingEffect {
    RingEffect::Ended {
        call_id: call_id.to_string(),
        outcome,
    }
}

/// Start ringing for an offer that may ring: the effects and the new state.
fn start_ringing(
    call_id: &str,
    conversation: &str,
    sender: &str,
    media: CallMedia,
    one_to_one: bool,
    effects: &mut Vec<RingEffect>,
) -> RingState {
    effects.push(RingEffect::Ring {
        call_id: call_id.to_string(),
        media,
        caller: sender.to_string(),
    });
    effects.push(RingEffect::ArmTimeout {
        call_id: call_id.to_string(),
        after_ms: CALL_RING_TIMEOUT_MS,
    });
    RingState::Ringing {
        call_id: call_id.to_string(),
        conversation: conversation.to_string(),
        media,
        caller: sender.to_string(),
        one_to_one,
    }
}

/// Answer busy to an offer for another call. In a 1:1, one `busy` to the
/// conversation, which my other devices read as busy elsewhere.
fn reply_busy(call_id: &str, one_to_one: bool, effects: &mut Vec<RingEffect>) {
    if one_to_one {
        effects.push(hangup(
            RingTarget::Conversation,
            call_id,
            HangupReason::Busy,
        ));
    } else {
        effects.push(hangup(
            RingTarget::OwnDevices,
            call_id,
            HangupReason::BusyElsewhere,
        ));
    }
    effects.push(ended(call_id, RingOutcome::Missed));
}

/// One step of the reducer.
pub fn ring_step(state: &RingState, event: &RingEvent) -> RingStep {
    let mut effects = Vec::new();
    let next = step(state, event, &mut effects);
    RingStep {
        state: next,
        effects,
    }
}

fn step(state: &RingState, event: &RingEvent, effects: &mut Vec<RingEffect>) -> RingState {
    match event {
        RingEvent::PlaceCall {
            call_id,
            conversation,
            media,
            member_count,
            one_to_one,
            now_ms,
        } => {
            if *state != RingState::Idle {
                effects.push(RingEffect::Refused {
                    call_id: call_id.clone(),
                });
                return state.clone();
            }
            effects.push(RingEffect::Join {
                call_id: call_id.clone(),
            });
            effects.push(RingEffect::Send {
                to: RingTarget::Conversation,
                signal: signal(
                    call_id,
                    CallSignalBodyJson::Offer {
                        media: *media,
                        ring: *one_to_one || should_ring(*member_count),
                        created_at_ms: *now_ms,
                    },
                ),
            });
            if *one_to_one {
                effects.push(RingEffect::ArmTimeout {
                    call_id: call_id.clone(),
                    after_ms: CALL_RING_TIMEOUT_MS,
                });
                RingState::Outgoing {
                    call_id: call_id.clone(),
                    conversation: conversation.clone(),
                    media: *media,
                }
            } else {
                RingState::InCall {
                    call_id: call_id.clone(),
                    conversation: conversation.clone(),
                    media: *media,
                    one_to_one: false,
                    rang: should_ring(*member_count),
                }
            }
        }

        RingEvent::Offer {
            call_id,
            conversation,
            sender,
            from_self,
            media,
            ring,
            age_ms,
            created_at_ms,
            now_ms,
            member_count,
            one_to_one,
            gate,
            already_ended,
            early_hangup,
        } => {
            // My own other device started it: never ring for myself. A call
            // this device already recorded as over never rings again.
            if *from_self || *already_ended {
                return state.clone();
            }
            // The same offer again (a redelivery): nothing new.
            if state.call_id() == Some(call_id.as_str()) {
                return state.clone();
            }
            let rings = *one_to_one || (*ring && should_ring(*member_count));
            match gate {
                RingGate::Blocked => return state.clone(),
                RingGate::NeedsPermission => {
                    if *one_to_one {
                        effects.push(hangup(
                            RingTarget::Conversation,
                            call_id,
                            HangupReason::NeedPermission,
                        ));
                    }
                    if rings {
                        effects.push(ended(call_id, RingOutcome::Missed));
                    }
                    return state.clone();
                }
                RingGate::Allowed => {}
            }
            // Its Hangup beat it here: the ring it would have been ends as
            // that Hangup would have ended it, without ever ringing.
            if rings {
                if let Some(h) = early_hangup {
                    if let Some(outcome) = ring_ended_by(sender, &h.sender, h.from_self, h.reason) {
                        effects.push(ended(call_id, outcome));
                        return state.clone();
                    }
                }
            }
            if !offer_is_fresh(*age_ms, *created_at_ms, *now_ms) {
                if rings {
                    effects.push(ended(call_id, RingOutcome::Missed));
                }
                return state.clone();
            }
            if !rings {
                effects.push(RingEffect::Notice {
                    call_id: call_id.clone(),
                    media: *media,
                    caller: sender.clone(),
                });
                return state.clone();
            }
            match state {
                RingState::Idle => {
                    start_ringing(call_id, conversation, sender, *media, *one_to_one, effects)
                }
                RingState::Outgoing {
                    call_id: mine,
                    conversation: my_conversation,
                    ..
                } if *one_to_one && my_conversation == conversation => {
                    // Glare: both sides of one 1:1 called at once. Call ids
                    // are fixed-length lower-case hex, so comparing the
                    // strings compares the ids.
                    let mine_lower = mine.to_ascii_lowercase();
                    let theirs = call_id.to_ascii_lowercase();
                    if mine_lower > theirs {
                        state.clone()
                    } else {
                        effects.push(hangup(RingTarget::Conversation, mine, HangupReason::Normal));
                        effects.push(RingEffect::Leave {
                            call_id: mine.clone(),
                        });
                        effects.push(ended(mine, RingOutcome::Glare));
                        if mine_lower == theirs {
                            reply_busy(call_id, true, effects);
                            RingState::Idle
                        } else {
                            start_ringing(call_id, conversation, sender, *media, true, effects)
                        }
                    }
                }
                RingState::InCall {
                    call_id: mine,
                    conversation: my_conversation,
                    one_to_one: true,
                    ..
                } if *one_to_one && my_conversation == conversation => {
                    // Re-call: the other side ended and called again before
                    // its hangup reached this device.
                    effects.push(RingEffect::Leave {
                        call_id: mine.clone(),
                    });
                    effects.push(ended(mine, RingOutcome::Completed));
                    start_ringing(call_id, conversation, sender, *media, true, effects)
                }
                _ => {
                    reply_busy(call_id, *one_to_one, effects);
                    state.clone()
                }
            }
        }

        RingEvent::Answer {
            call_id,
            conversation: from,
            from_self,
            ..
        } => match state {
            RingState::Ringing { call_id: mine, .. } if mine == call_id && *from_self => {
                effects.push(RingEffect::StopRinging {
                    call_id: call_id.clone(),
                });
                effects.push(ended(call_id, RingOutcome::AnsweredElsewhere));
                RingState::Idle
            }
            RingState::Outgoing {
                call_id: mine,
                conversation,
                media,
            } if mine == call_id && !*from_self && conversation == from => {
                effects.push(RingEffect::PeerAnswered {
                    call_id: call_id.clone(),
                });
                RingState::InCall {
                    call_id: call_id.clone(),
                    conversation: conversation.clone(),
                    media: *media,
                    one_to_one: true,
                    rang: false,
                }
            }
            _ => state.clone(),
        },

        RingEvent::Hangup {
            call_id,
            conversation: from,
            sender,
            from_self,
            reason,
        } => match state {
            RingState::Ringing {
                call_id: mine,
                caller,
                ..
            } if mine == call_id => match ring_ended_by(caller, sender, *from_self, *reason) {
                Some(outcome) => {
                    effects.push(RingEffect::StopRinging {
                        call_id: call_id.clone(),
                    });
                    effects.push(ended(call_id, outcome));
                    RingState::Idle
                }
                None => state.clone(),
            },
            RingState::Outgoing {
                call_id: mine,
                conversation,
                ..
            } if mine == call_id && !*from_self && conversation == from => {
                let outcome = match reason {
                    HangupReason::Busy => Some(RingOutcome::RemoteBusy),
                    HangupReason::Declined | HangupReason::Normal => {
                        Some(RingOutcome::RemoteDeclined)
                    }
                    HangupReason::NeedPermission => Some(RingOutcome::NeedsPermission),
                    // The callee's own devices' business, not the caller's.
                    HangupReason::AcceptedElsewhere
                    | HangupReason::DeclinedElsewhere
                    | HangupReason::BusyElsewhere => None,
                };
                match outcome {
                    Some(outcome) => {
                        effects.push(RingEffect::Leave {
                            call_id: call_id.clone(),
                        });
                        effects.push(ended(call_id, outcome));
                        RingState::Idle
                    }
                    None => state.clone(),
                }
            }
            RingState::InCall {
                call_id: mine,
                conversation,
                one_to_one: true,
                ..
            } if mine == call_id
                && !*from_self
                && conversation == from
                && *reason == HangupReason::Normal =>
            {
                effects.push(RingEffect::Leave {
                    call_id: call_id.clone(),
                });
                effects.push(ended(call_id, RingOutcome::Completed));
                RingState::Idle
            }
            // A Hangup for a call this device is not on: it may have beaten
            // its own Offer here. Kept, so that Offer never rings.
            _ if state.call_id() != Some(call_id.as_str()) => {
                effects.push(RingEffect::RememberHangup {
                    call_id: call_id.clone(),
                    hangup: EarlyHangup {
                        sender: sender.clone(),
                        from_self: *from_self,
                        reason: *reason,
                    },
                });
                state.clone()
            }
            _ => state.clone(),
        },

        RingEvent::Accept => match state {
            RingState::Ringing {
                call_id,
                conversation,
                media,
                one_to_one,
                ..
            } => {
                effects.push(RingEffect::StopRinging {
                    call_id: call_id.clone(),
                });
                effects.push(RingEffect::Join {
                    call_id: call_id.clone(),
                });
                if *one_to_one {
                    // One answer to the conversation: the caller's device
                    // takes it, and my other devices read it as answered
                    // elsewhere.
                    effects.push(RingEffect::Send {
                        to: RingTarget::Conversation,
                        signal: signal(call_id, CallSignalBodyJson::Answer),
                    });
                } else {
                    effects.push(hangup(
                        RingTarget::OwnDevices,
                        call_id,
                        HangupReason::AcceptedElsewhere,
                    ));
                }
                RingState::InCall {
                    call_id: call_id.clone(),
                    conversation: conversation.clone(),
                    media: *media,
                    one_to_one: *one_to_one,
                    rang: false,
                }
            }
            _ => state.clone(),
        },

        RingEvent::Decline => match state {
            RingState::Ringing {
                call_id,
                one_to_one,
                ..
            } => {
                effects.push(RingEffect::StopRinging {
                    call_id: call_id.clone(),
                });
                if *one_to_one {
                    effects.push(hangup(
                        RingTarget::Conversation,
                        call_id,
                        HangupReason::Declined,
                    ));
                } else {
                    effects.push(hangup(
                        RingTarget::OwnDevices,
                        call_id,
                        HangupReason::DeclinedElsewhere,
                    ));
                }
                effects.push(ended(call_id, RingOutcome::Declined));
                RingState::Idle
            }
            _ => state.clone(),
        },

        RingEvent::HangUp { alone } => match state {
            RingState::Idle => RingState::Idle,
            // Hanging up while ringing is declining.
            RingState::Ringing { .. } => step(state, &RingEvent::Decline, effects),
            RingState::Outgoing { call_id, .. } => {
                effects.push(hangup(
                    RingTarget::Conversation,
                    call_id,
                    HangupReason::Normal,
                ));
                effects.push(RingEffect::Leave {
                    call_id: call_id.clone(),
                });
                effects.push(ended(call_id, RingOutcome::Cancelled));
                RingState::Idle
            }
            RingState::InCall {
                call_id,
                one_to_one,
                rang,
                ..
            } => {
                // A 1:1 always tells the other side. A group caller still
                // alone in the call cancels the ring it sent, so nobody keeps
                // ringing into an empty room; once anyone joined, the ring
                // stands and others may still join.
                if *one_to_one || (*rang && *alone) {
                    effects.push(hangup(
                        RingTarget::Conversation,
                        call_id,
                        HangupReason::Normal,
                    ));
                }
                effects.push(RingEffect::Leave {
                    call_id: call_id.clone(),
                });
                effects.push(ended(call_id, RingOutcome::Completed));
                RingState::Idle
            }
        },

        RingEvent::Timeout { call_id } => match state {
            RingState::Ringing { call_id: mine, .. } if mine == call_id => {
                effects.push(RingEffect::StopRinging {
                    call_id: call_id.clone(),
                });
                effects.push(ended(call_id, RingOutcome::Missed));
                RingState::Idle
            }
            RingState::Outgoing { call_id: mine, .. } if mine == call_id => {
                effects.push(hangup(
                    RingTarget::Conversation,
                    call_id,
                    HangupReason::Normal,
                ));
                effects.push(RingEffect::Leave {
                    call_id: call_id.clone(),
                });
                effects.push(ended(call_id, RingOutcome::NoAnswer));
                RingState::Idle
            }
            _ => state.clone(),
        },
    }
}

/// The JSON door: `state_json` (a [`RingState`]; `null` or `""` is idle) and
/// `event_json` (a [`RingEvent`]) in, `{"state":…,"effects":[…]}` out. An
/// event or state it cannot read is an error, never a silent no-op.
pub fn ring_step_json(state_json: &str, event_json: &str) -> Result<String> {
    let trimmed = state_json.trim();
    let state: RingState = if trimmed.is_empty() || trimmed == "null" {
        RingState::Idle
    } else {
        serde_json::from_str(trimmed)
            .map_err(|err| Error::invalid(format!("could not read the ring state: {err}")))?
    };
    let event: RingEvent = serde_json::from_str(event_json)
        .map_err(|err| Error::invalid(format!("could not read the ring event: {err}")))?;
    serde_json::to_string(&ring_step(&state, &event))
        .map_err(|err| Error::invalid(format!("could not write the ring step: {err}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const A: &str = "0000000000000000000000000000000a";
    const B: &str = "0000000000000000000000000000000b";

    fn offer(call_id: &str, members: u32, one_to_one: bool) -> RingEvent {
        RingEvent::Offer {
            call_id: call_id.into(),
            conversation: "c".into(),
            sender: "ava".into(),
            from_self: false,
            media: CallMedia::Video,
            ring: true,
            age_ms: 0,
            created_at_ms: 1_789_516_800_000,
            now_ms: 1_789_516_800_000,
            member_count: members,
            one_to_one,
            gate: RingGate::Allowed,
            already_ended: false,
            early_hangup: None,
        }
    }

    fn hangup_event(
        call_id: &str,
        sender: &str,
        from_self: bool,
        reason: HangupReason,
    ) -> RingEvent {
        RingEvent::Hangup {
            call_id: call_id.into(),
            conversation: "c".into(),
            sender: sender.into(),
            from_self,
            reason,
        }
    }

    fn after(event: &RingEvent, early: Option<EarlyHangup>) -> RingEvent {
        let mut event = event.clone();
        if let RingEvent::Offer { early_hangup, .. } = &mut event {
            *early_hangup = early;
        }
        event
    }

    #[test]
    fn a_hangup_before_its_offer_is_kept_and_the_offer_never_rings() {
        // The caller's cancel arrives first, while this device rings nothing.
        let early = ring_step(
            &RingState::Idle,
            &hangup_event(A, "ava", false, HangupReason::Normal),
        );
        assert_eq!(early.state, RingState::Idle);
        let kept = EarlyHangup {
            sender: "ava".into(),
            from_self: false,
            reason: HangupReason::Normal,
        };
        assert_eq!(
            early.effects,
            vec![RingEffect::RememberHangup {
                call_id: A.into(),
                hangup: kept.clone()
            }]
        );
        // Its Offer, drained later and still fresh: a missed call, no ring.
        let late = ring_step(&RingState::Idle, &after(&offer(A, 2, true), Some(kept)));
        assert_eq!(late.state, RingState::Idle);
        assert_eq!(late.effects, vec![ended(A, RingOutcome::Missed)]);
    }

    #[test]
    fn an_answer_elsewhere_before_the_offer_never_rings_here() {
        let kept = EarlyHangup {
            sender: "me".into(),
            from_self: true,
            reason: HangupReason::AcceptedElsewhere,
        };
        let step = ring_step(&RingState::Idle, &after(&offer(A, 2, true), Some(kept)));
        assert_eq!(step.state, RingState::Idle);
        assert_eq!(step.effects, vec![ended(A, RingOutcome::AnsweredElsewhere)]);
    }

    #[test]
    fn another_members_hangup_before_a_group_offer_still_rings() {
        let kept = EarlyHangup {
            sender: "bo".into(),
            from_self: false,
            reason: HangupReason::Normal,
        };
        let step = ring_step(&RingState::Idle, &after(&offer(A, 4, false), Some(kept)));
        assert!(matches!(step.state, RingState::Ringing { .. }));
    }

    #[test]
    fn a_hangup_for_the_call_in_hand_is_not_kept() {
        let ringing = ring_step(&RingState::Idle, &offer(A, 4, false)).state;
        // Another member leaves the group call ringing here: nothing to keep.
        let step = ring_step(
            &ringing,
            &hangup_event(A, "bo", false, HangupReason::Normal),
        );
        assert_eq!(step.state, ringing);
        assert!(step.effects.is_empty());
        // A different call's hangup while this one rings is kept.
        let other = ring_step(
            &ringing,
            &hangup_event(B, "bo", false, HangupReason::Normal),
        );
        assert_eq!(other.state, ringing);
        assert!(matches!(
            other.effects[..],
            [RingEffect::RememberHangup { .. }]
        ));
    }

    #[test]
    fn a_second_offer_while_ringing_is_busy() {
        let ringing = ring_step(&RingState::Idle, &offer(A, 2, true)).state;
        let step = ring_step(&ringing, &offer(B, 2, true));
        assert_eq!(step.state, ringing);
        assert!(step
            .effects
            .contains(&hangup(RingTarget::Conversation, B, HangupReason::Busy)));
    }

    #[test]
    fn seventeen_people_get_a_notice() {
        let step = ring_step(&RingState::Idle, &offer(A, 17, false));
        assert_eq!(step.state, RingState::Idle);
        assert!(matches!(step.effects[..], [RingEffect::Notice { .. }]));
        let step = ring_step(&RingState::Idle, &offer(A, 16, false));
        assert!(matches!(step.state, RingState::Ringing { .. }));
    }

    fn rings_or_joins(effects: &[RingEffect]) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, RingEffect::Ring { .. } | RingEffect::Join { .. }))
    }

    #[test]
    fn a_stale_offer_never_rings_or_joins() {
        let mut stale = offer(A, 2, true);
        if let RingEvent::Offer { age_ms, .. } = &mut stale {
            *age_ms = CALL_OFFER_MAX_AGE_MS as i64 + 1;
        }
        let step = ring_step(&RingState::Idle, &stale);
        assert_eq!(step.state, RingState::Idle);
        assert!(!rings_or_joins(&step.effects));
        assert_eq!(step.effects, vec![ended(A, RingOutcome::Missed)]);
    }

    #[test]
    fn an_offer_for_a_call_already_over_does_nothing() {
        let mut over = offer(A, 2, true);
        if let RingEvent::Offer { already_ended, .. } = &mut over {
            *already_ended = true;
        }
        let step = ring_step(&RingState::Idle, &over);
        assert_eq!(step.state, RingState::Idle);
        assert!(step.effects.is_empty());
    }

    #[test]
    fn a_ring_joins_only_on_accept() {
        let step = ring_step(&RingState::Idle, &offer(A, 2, true));
        assert!(!step
            .effects
            .iter()
            .any(|e| matches!(e, RingEffect::Join { .. })));
        // The caller hangs up while it rings: over, never joined.
        let hung = ring_step(
            &step.state,
            &RingEvent::Hangup {
                call_id: A.into(),
                conversation: "c".into(),
                sender: "ava".into(),
                from_self: false,
                reason: HangupReason::Normal,
            },
        );
        assert_eq!(hung.state, RingState::Idle);
        assert!(!rings_or_joins(&hung.effects));
        // A timeout: over, never joined.
        let timed = ring_step(&step.state, &RingEvent::Timeout { call_id: A.into() });
        assert!(!rings_or_joins(&timed.effects));
        // Only the person's Accept joins.
        let accepted = ring_step(&step.state, &RingEvent::Accept);
        assert!(accepted
            .effects
            .contains(&RingEffect::Join { call_id: A.into() }));
    }

    /// A flood from the other side (the same Offer again, other members'
    /// hangups, offers for other calls, answers) never re-arms the ring
    /// timer or moves the ring, so the timeout and a decline still end it
    /// (docs/calls.md §Hanging up).
    #[test]
    fn a_flood_never_rearms_the_ring_or_holds_a_decline() {
        let first = ring_step(&RingState::Idle, &offer(A, 4, false));
        let ringing = first.state;
        let flood = [
            offer(A, 4, false),
            hangup_event(A, "bo", false, HangupReason::Normal),
            offer(B, 4, false),
            RingEvent::Answer {
                call_id: A.into(),
                conversation: "c".into(),
                sender: "bo".into(),
                from_self: false,
            },
            hangup_event(B, "ava", false, HangupReason::Normal),
        ];
        for i in 0..10_000 {
            let step = ring_step(&ringing, &flood[i % flood.len()]);
            assert_eq!(step.state, ringing, "event {i} moved the ring");
            assert!(
                !step
                    .effects
                    .iter()
                    .any(|e| matches!(e, RingEffect::ArmTimeout { .. } | RingEffect::Ring { .. })),
                "event {i} re-armed the ring: {:?}",
                step.effects
            );
        }
        let timed = ring_step(&ringing, &RingEvent::Timeout { call_id: A.into() });
        assert_eq!(timed.state, RingState::Idle);
        let declined = ring_step(&ringing, &RingEvent::Decline);
        assert_eq!(declined.state, RingState::Idle);
        assert!(declined
            .effects
            .contains(&RingEffect::StopRinging { call_id: A.into() }));
    }

    #[test]
    fn the_json_door_reads_null_as_idle() {
        let out = ring_step_json("null", r#"{"type":"hangUp"}"#).unwrap();
        assert_eq!(out, r#"{"state":{"phase":"idle"},"effects":[]}"#);
        assert!(ring_step_json("null", r#"{"type":"teleport"}"#).is_err());
    }

    /// A 1:1 call takes an `Answer` or `Hangup` only from its own
    /// conversation, whose only other account is the peer: an account that
    /// learned the call id and sends from a conversation it shares with this
    /// device declines, answers or hangs up nothing.
    #[test]
    fn a_one_to_one_call_takes_answers_and_hangups_only_from_its_conversation() {
        let outgoing = RingState::Outgoing {
            call_id: A.into(),
            conversation: "dm-with-ada".into(),
            media: CallMedia::Audio,
        };
        let in_call = RingState::InCall {
            call_id: A.into(),
            conversation: "dm-with-ada".into(),
            media: CallMedia::Audio,
            one_to_one: true,
            rang: false,
        };
        let hangup = |conversation: &str, reason| RingEvent::Hangup {
            call_id: A.into(),
            conversation: conversation.into(),
            sender: "actor-mallory".into(),
            from_self: false,
            reason,
        };
        let answer = |conversation: &str| RingEvent::Answer {
            call_id: A.into(),
            conversation: conversation.into(),
            sender: "actor-mallory".into(),
            from_self: false,
        };
        for (state, event) in [
            (&outgoing, hangup("dm-with-mallory", HangupReason::Declined)),
            (&outgoing, answer("dm-with-mallory")),
            (&in_call, hangup("dm-with-mallory", HangupReason::Normal)),
        ] {
            let step = ring_step(state, &event);
            assert_eq!(&step.state, state, "{event:?} moved the call");
            assert!(step.effects.is_empty(), "{event:?}: {:?}", step.effects);
        }
        // From the call's own conversation, the same events act.
        let declined = ring_step(&outgoing, &hangup("dm-with-ada", HangupReason::Declined));
        assert_eq!(declined.state, RingState::Idle);
        let answered = ring_step(&outgoing, &answer("dm-with-ada"));
        assert!(matches!(answered.state, RingState::InCall { .. }));
        let hung = ring_step(&in_call, &hangup("dm-with-ada", HangupReason::Normal));
        assert_eq!(hung.state, RingState::Idle);
    }
}
