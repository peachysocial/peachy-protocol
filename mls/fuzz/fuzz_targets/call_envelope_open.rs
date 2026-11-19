// SPDX-License-Identifier: MIT
//! The whole receive path a call byte takes, through the real door:
//! `Client::open_envelope`, kind 6, then `Client::open_call_signal` (lane
//! split; on the MLS lane the message parse and the application-only check;
//! on the live lane the exporter-keyed frame, its signature and the replay
//! window), then `decode_call_signal`. docs/mls-core.md §Fuzzing.
//!
//! The group holds Ada's device, the receiver, at leaf 0, Bo's at leaf 1 and
//! Cy's at leaf 2. The first input byte picks how far in the fuzzer's bytes
//! are placed (`mode % 4`), since no fuzzer forges an AEAD tag or a
//! signature:
//! - 0: the bytes are a mailbox envelope;
//! - 1: they are the inner bytes of a kind-6 envelope this group really sealed;
//! - 2: they are an encoded signal, unsigned, sealed under the group's real
//!   live key and wrapped in a real envelope. The stamp claims Ada's, Bo's or
//!   Cy's leaf or a leaf outside the tree, by the next two bits;
//! - 3: the same, claiming Bo's leaf (or Cy's, by the next bit but one) and
//!   signed with that leaf's key, the signature spoiled when the next bit
//!   says so.
//!
//! Whatever opens must keep the lane rule: only `Joined`, `Left` and unknown
//! bodies come out of the live lane, and nothing from the live lane names a
//! sender or a leaf. The MLS lane may carry any body (a signed `Joined`,
//! threat model D10), always with its sender and the sender's leaf, and a
//! signed `Joined` names that leaf. A live-sealed signal opens to exactly what
//! `decode_call_signal` reads from it, never twice, or is refused: for its
//! lane, for a claimed leaf outside the tree, for a `Joined` naming a leaf
//! other than its frame's, for a signature field that does not hold, for an
//! unsigned frame claiming a leaf once it has been seen signing, or for
//! being a `Left`. A live `Left` opens only for a participant
//! bound with no call key, and only a signed `Joined` on the MLS lane binds
//! one; nothing here sends one, so every live `Left` is refused. A signed
//! frame opens whenever an unsigned one would.
//!
//! The window keeps one record per (group, leaf), so a leaf's record goes
//! only for its own frames: the first frame each leaf signed is replayed
//! after every input, and must stay refused while fewer frames from that
//! leaf have opened since than a record keeps.

#![no_main]

mod common;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use common::{device, issuer, GROUP, NOW};
use libfuzzer_sys::fuzz_target;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::SignatureScheme;
use peachy_mls_core::call::replay::MAX_SEEN;
use peachy_mls_core::call::{
    append_live_signature, decode_call_signal, live_signature_statement,
    seal_live_frame_with_nonce, split_live_signature, CallLane, CallSignalBody, LiveStamp,
    CALL_LIVE_EXPORTER_LABEL, CALL_LIVE_KEY_BYTES, CALL_LIVE_MAX_SKEW_MS,
};
use peachy_mls_core::envelope::{seal_envelope_with_nonce, ENVELOPE_KIND_CALL};
use peachy_mls_core::Client;

const NONCE: [u8; 12] = [5; 12];
/// Bo's and Cy's device seeds, as `common::device` makes them from a number.
const BO: u8 = 2;
const CY: u8 = 3;

struct Member {
    client: Client,
    live_key: Vec<u8>,
    epoch: u64,
}

fn member() -> Member {
    let issuer = issuer();
    let mut client = device(&issuer, 1, "actor-ada", "device-ada");
    client.create_group(GROUP).expect("a group");
    for (n, actor, name, leaf) in [
        (BO, "actor-bo", "device-bo", BO_LEAF),
        (CY, "actor-cy", "device-cy", CY_LEAF),
    ] {
        let other = device(&issuer, n, actor, name);
        let package = other.generate_key_package().expect("a key package");
        client.add_member(GROUP, &package).expect("Ada adds them");
        client.merge_pending_commit(GROUP).expect("and merges");
        assert_eq!(client.leaf_of_device(GROUP, name).expect("a leaf"), leaf);
    }
    let live_key = client
        .export_secret(GROUP, CALL_LIVE_EXPORTER_LABEL, &[], CALL_LIVE_KEY_BYTES)
        .expect("the live key");
    let epoch = client.epoch(GROUP).expect("epoch");
    Member {
        client,
        live_key,
        epoch,
    }
}

/// The first frame a leaf signed that opened: its kind-6 inner bytes, and
/// how many frames from that leaf have opened since, in any call.
struct First {
    inner: Vec<u8>,
    frames: usize,
}

thread_local! {
    static MEMBER: RefCell<Member> = RefCell::new(member());
    static SENT: Cell<u64> = const { Cell::new(0) };
    /// The leaves Ada has opened a signed live frame from: from then on an
    /// unsigned one claiming that leaf is refused.
    static SIGNERS: RefCell<BTreeSet<u32>> = const { RefCell::new(BTreeSet::new()) };
    static FIRST: RefCell<BTreeMap<u32, First>> = const { RefCell::new(BTreeMap::new()) };
}

/// Ada's own leaf, Bo's and Cy's.
const OWN_LEAF: u32 = 0;
const BO_LEAF: u32 = 1;
const CY_LEAF: u32 = 2;

/// How many stamps the clock bound holds: one input takes at most one.
const STAMPS: u64 = 2 * CALL_LIVE_MAX_SKEW_MS + 1;

/// A fresh stamp for `leaf`: never one the window has held. The stamps walk
/// the clock bound once; the clock is fixed, so the window forgets nothing
/// by age, and a stamp coming round again could be a true duplicate. So
/// before that, [`start_over`] gives Ada a new window.
fn next_stamp(leaf: u32) -> LiveStamp {
    let n = SENT.with(|sent| {
        let n = sent.get();
        sent.set(n + 1);
        n
    });
    assert!(n < STAMPS, "a stamp came round again");
    let now_ms = u64::try_from(NOW).expect("positive") * 1000;
    LiveStamp {
        sender_leaf: leaf,
        sent_at_ms: now_ms - CALL_LIVE_MAX_SKEW_MS + n,
    }
}

/// Once every stamp has been used: Ada afresh, and all the oracle knew.
fn start_over() {
    if SENT.with(Cell::get) < STAMPS {
        return;
    }
    MEMBER.with(|cell| *cell.borrow_mut() = member());
    SENT.with(|sent| sent.set(0));
    SIGNERS.with(|signers| signers.borrow_mut().clear());
    FIRST.with(|first| first.borrow_mut().clear());
}

/// `signal` with the live signature of the device seeded `n` over it,
/// spoiled when `spoil`.
fn signed_by(n: u8, epoch: u64, stamp: LiveStamp, signal: &[u8], spoil: bool) -> Vec<u8> {
    let mut seed = [0u8; 32];
    seed[0] = n;
    let statement = live_signature_statement(GROUP, epoch, stamp, signal);
    let signature = RustCrypto::default()
        .sign(SignatureScheme::ED25519, &statement, &seed)
        .expect("the leaf signs");
    let mut signature: [u8; 64] = signature.try_into().expect("64 bytes");
    if spoil {
        signature[0] ^= 1;
    }
    let mut out = signal.to_vec();
    append_live_signature(&mut out, &signature);
    out
}

fn envelope(inner: &[u8]) -> Vec<u8> {
    seal_envelope_with_nonce(GROUP, ENVELOPE_KIND_CALL, inner, &NONCE).expect("seals")
}

/// The live-sealed signal a mode-2 or mode-3 input carries.
struct Live<'a> {
    raw: &'a [u8],
    leaf: u32,
    /// The leaf's signature is on it, and holds.
    signed: bool,
    /// The leaf's signature is on it, spoiled.
    spoiled: bool,
}

/// What a live frame that opened tells the oracle: a signed one marks its
/// leaf as signing, and the first one is kept to replay.
fn note_opened(leaf: u32, signed: bool, inner: &[u8]) {
    if signed {
        SIGNERS.with(|signers| signers.borrow_mut().insert(leaf));
    }
    FIRST.with(|first| {
        let mut first = first.borrow_mut();
        match first.get_mut(&leaf) {
            Some(first) => first.frames += 1,
            None if signed => {
                first.insert(
                    leaf,
                    First {
                        inner: inner.to_vec(),
                        frames: 1,
                    },
                );
            }
            None => {}
        }
    });
}

/// Each signing leaf's first frame, replayed: still refused while its
/// record has not had to make room for that leaf's own later frames.
fn replay_firsts(client: &mut Client) {
    let firsts: Vec<(u32, Vec<u8>, usize)> = FIRST.with(|first| {
        first
            .borrow()
            .iter()
            .map(|(leaf, first)| (*leaf, first.inner.clone(), first.frames))
            .collect()
    });
    for (leaf, inner, frames) in firsts {
        if frames >= MAX_SEEN {
            continue;
        }
        assert!(
            client.open_call_signal(GROUP, &inner).is_err(),
            "leaf {leaf}'s first signed frame opened again: its record was pushed out"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    start_over();
    MEMBER.with(|cell| {
        let member = &mut *cell.borrow_mut();
        let (bytes, live) = match mode % 4 {
            0 => (rest.to_vec(), None),
            1 => (envelope(rest), None),
            2 => {
                let leaf = match (mode >> 2) & 3 {
                    0 => OWN_LEAF,
                    1 => BO_LEAF,
                    2 => CY_LEAF,
                    _ => 3 + u32::from(mode >> 4),
                };
                let Ok(frame) =
                    seal_live_frame_with_nonce(&member.live_key, next_stamp(leaf), rest, &NONCE)
                else {
                    return;
                };
                let live = Live {
                    raw: rest,
                    leaf,
                    signed: false,
                    spoiled: false,
                };
                (envelope(&frame), Some(live))
            }
            _ => {
                let spoil = (mode >> 2) & 1 == 1;
                let (n, leaf) = if (mode >> 3) & 1 == 1 {
                    (CY, CY_LEAF)
                } else {
                    (BO, BO_LEAF)
                };
                let stamp = next_stamp(leaf);
                let signed = signed_by(n, member.epoch, stamp, rest, spoil);
                let Ok(frame) =
                    seal_live_frame_with_nonce(&member.live_key, stamp, &signed, &NONCE)
                else {
                    return;
                };
                let live = Live {
                    raw: rest,
                    leaf,
                    signed: !spoil,
                    spoiled: spoil,
                };
                (envelope(&frame), Some(live))
            }
        };
        let Ok(Some(opened)) = member.client.open_envelope(&bytes) else {
            assert!(mode % 4 == 0, "an envelope this group sealed did not open");
            return;
        };
        assert_eq!(opened.group_id, GROUP);
        if opened.kind != ENVELOPE_KIND_CALL {
            return;
        }
        let result = member.client.open_call_signal(GROUP, &opened.inner);
        // A call envelope never moves the group.
        assert_eq!(member.client.epoch(GROUP).expect("epoch"), member.epoch);
        match result {
            Ok(call) => {
                if call.lane == CallLane::Live {
                    assert!(
                        !call.signal.body.is_mls_lane(),
                        "a ring-lane body came off the live lane"
                    );
                    assert!(call.sender.is_none(), "a live frame named a sender");
                    assert!(call.sender_leaf.is_none(), "a live frame named a leaf");
                    assert!(
                        !matches!(call.signal.body, CallSignalBody::Left { .. }),
                        "a live Left opened for a participant nobody bound"
                    );
                } else {
                    // Any body may be signed (D10); a signed one names its
                    // sender and the sender's own leaf.
                    assert!(call.sender.is_some(), "an MLS-lane signal without a sender");
                    let leaf = call.sender_leaf.expect("an MLS-lane signal names its leaf");
                    if let CallSignalBody::Joined { leaf_index, .. } = &call.signal.body {
                        assert_eq!(*leaf_index, leaf, "a signed Joined named another leaf");
                    }
                }
                if let Some(live) = live {
                    assert_eq!(call.lane, CallLane::Live);
                    assert!(
                        live.leaf == OWN_LEAF || live.leaf == BO_LEAF || live.leaf == CY_LEAF,
                        "a live frame from outside the tree opened"
                    );
                    assert!(
                        !live.spoiled,
                        "a live frame opened under a spoiled signature"
                    );
                    if let CallSignalBody::Joined { leaf_index, .. } = &call.signal.body {
                        assert_eq!(*leaf_index, live.leaf, "a live Joined named another leaf");
                    }
                    note_opened(live.leaf, live.signed, &opened.inner);
                    if !live.signed {
                        assert!(
                            !SIGNERS.with(|signers| signers.borrow().contains(&live.leaf)),
                            "an unsigned frame claiming a leaf seen signing opened"
                        );
                    }
                    assert_eq!(Some(call.signal), decode_call_signal(live.raw).ok());
                    // The same frame again is a replay (threat model D3).
                    assert!(
                        member
                            .client
                            .open_call_signal(GROUP, &opened.inner)
                            .is_err(),
                        "a live frame opened twice"
                    );
                }
            }
            Err(_) => {
                if let Some(live) = live {
                    refused(&live);
                }
            }
        }
        replay_firsts(&mut member.client);
    });
});

/// A live-sealed signal that was refused: only because it does not decode,
/// for its lane, for a leaf outside the tree, for a Joined naming a leaf
/// other than its frame's, for a signature field (one the fuzzer wrote, or a
/// spoiled one), for claiming a signing leaf unsigned, or for a Left
/// (nobody is bound keyless).
fn refused(live: &Live<'_>) {
    if live.spoiled {
        return;
    }
    let unsigned = matches!(split_live_signature(live.raw), Ok((_, None)));
    let Ok(signal) = decode_call_signal(live.raw) else {
        return;
    };
    if !unsigned {
        return;
    }
    let joined_elsewhere = matches!(
        &signal.body,
        CallSignalBody::Joined { leaf_index, .. } if *leaf_index != live.leaf
    );
    let left = matches!(&signal.body, CallSignalBody::Left { .. });
    let silenced = !live.signed && SIGNERS.with(|signers| signers.borrow().contains(&live.leaf));
    assert!(
        signal.body.is_mls_lane()
            || (live.leaf != OWN_LEAF && live.leaf != BO_LEAF && live.leaf != CY_LEAF)
            || joined_elsewhere
            || left
            || silenced,
        "a live signal was refused: {signal:?}"
    );
}
