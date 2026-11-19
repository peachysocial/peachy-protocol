// SPDX-License-Identifier: MIT
//! Typing frames name their author with a signature, and a receiver takes
//! each once while it remembers its stamp
//! (docs/sealed-messages.md §Typing inside the group).
//!
//! 1. A member's frame opens for the others, to its words, attributed to the
//!    person whose leaf signed it, from either of that person's devices.
//! 2. A member cannot show another member typing: a frame whose `u` names
//!    someone whose leaf did not sign it is dropped.
//! 3. A frame is taken once: the same bytes again (the server holding a
//!    recording) are dropped, and so is one more than two minutes old or
//!    ahead.
//! 4. A frame does not cross groups or epochs.
//! 5. A frame without a signature and a stamp is dropped.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::typing::{
    encode_typing, open_typing_wire, parse_typing, seal_typing_wire, OpenedTyping, TypingFrame,
    TYPING_BLOCK, TYPING_EXPORTER_LABEL, TYPING_KEY_BYTES, TYPING_NONCE_BYTES,
};
use peachy_mls_core::Client;
use support::{advance_ms, client, issuer, step_wall_ms};

const G: &[u8] = b"peachy-group-typing-authenticity";
const OTHER: &[u8] = b"peachy-group-typing-other";
const ADA: &str = "5b0f5a52-8a55-4a5b-9d59-1b9a7a3f0c11";
const BO: &str = "0f3c6d2e-1111-4222-8333-944455556666";
const CY: &str = "7c1d2e3f-2222-4333-8444-a55566667777";

/// Ada (two devices), Bo and Cy in `G`; Ada's phone and Bo in `OTHER`.
struct World {
    ada: Client,
    ada_laptop: Client,
    bo: Client,
    cy: Client,
}

fn add(group: &[u8], adder: &mut Client, others: &mut [&mut Client], joiner: &mut Client) {
    let kp = joiner.generate_key_package().unwrap();
    let bundle = adder.add_member(group, &kp).unwrap();
    adder.merge_pending_commit(group).unwrap();
    for other in others.iter_mut() {
        other.process_commit(group, &bundle.commit).unwrap();
    }
    joiner.join_from_welcome(&bundle.welcome.unwrap()).unwrap();
}

fn world() -> World {
    let s = issuer();
    let mut ada = client(&s, 1, ADA, "11111111-aaaa-4aaa-8aaa-111111111111");
    let mut ada_laptop = client(&s, 2, ADA, "11111111-aaaa-4aaa-8aaa-222222222222");
    let mut bo = client(&s, 3, BO, "22222222-bbbb-4bbb-8bbb-222222222222");
    let mut cy = client(&s, 4, CY, "33333333-cccc-4ccc-8ccc-333333333333");
    ada.create_group(G).unwrap();
    add(G, &mut ada, &mut [], &mut bo);
    add(G, &mut ada, &mut [&mut bo], &mut cy);
    add(G, &mut ada, &mut [&mut bo, &mut cy], &mut ada_laptop);
    ada.create_group(OTHER).unwrap();
    let mut none: [&mut Client; 0] = [];
    add(OTHER, &mut ada, &mut none, &mut bo);
    World {
        ada,
        ada_laptop,
        bo,
        cy,
    }
}

fn opened(actor: &str, typing: bool) -> Option<OpenedTyping> {
    Some(OpenedTyping {
        actor_id: actor.to_owned(),
        typing,
    })
}

fn key(c: &Client, group: &[u8]) -> Vec<u8> {
    c.export_secret(group, TYPING_EXPORTER_LABEL, group, TYPING_KEY_BYTES)
        .unwrap()
}

/// What a member holding the group's typing key can make of someone else's
/// frame: open it, change its words, seal it again.
fn rewrite(c: &Client, frame: &[u8], change: impl FnOnce(&mut TypingFrame)) -> Vec<u8> {
    let k = key(c, G);
    let mut words = parse_typing(&open_typing_wire(&k, frame).unwrap()).unwrap();
    change(&mut words);
    seal_typing_wire(&k, &[9u8; TYPING_NONCE_BYTES], &encode_typing(&words)).unwrap()
}

#[test]
fn a_frame_opens_for_the_others_attributed_to_its_signer() {
    let mut w = world();
    let start = w.ada.seal_typing(G, true).unwrap();
    assert_eq!(start.len(), TYPING_NONCE_BYTES + 2 * TYPING_BLOCK + 16);
    assert_eq!(w.bo.open_typing(G, &start).unwrap(), opened(ADA, true));
    assert_eq!(w.cy.open_typing(G, &start).unwrap(), opened(ADA, true));
    let stop = w.ada.seal_typing(G, false).unwrap();
    assert_eq!(stop.len(), start.len());
    assert_eq!(w.bo.open_typing(G, &stop).unwrap(), opened(ADA, false));
    // From the person's other device: another leaf, the same person.
    let laptop = w.ada_laptop.seal_typing(G, true).unwrap();
    assert_eq!(w.bo.open_typing(G, &laptop).unwrap(), opened(ADA, true));
    // A device's own person comes back too; the client drops it by name.
    assert_eq!(w.ada.open_typing(G, &laptop).unwrap(), opened(ADA, true));
}

#[test]
fn a_member_cannot_show_another_member_typing() {
    let mut w = world();
    // Cy takes its own signed frame and puts Bo's name on it.
    let own = w.cy.seal_typing(G, true).unwrap();
    let as_bo = rewrite(&w.cy, &own, |f| f.actor_id = BO.to_owned());
    assert_eq!(w.ada.open_typing(G, &as_bo).unwrap(), None);
    // Or keeps the name and changes what it says.
    let flipped = rewrite(&w.cy, &own, |f| f.typing = false);
    assert_eq!(w.ada.open_typing(G, &flipped).unwrap(), None);
    // Or re-stamps it.
    let restamped = rewrite(&w.cy, &own, |f| f.stamp_ms = f.stamp_ms.map(|s| s + 1));
    assert_eq!(w.ada.open_typing(G, &restamped).unwrap(), None);
    // Cy's own frame, untouched, is Cy's.
    assert_eq!(w.ada.open_typing(G, &own).unwrap(), opened(CY, true));
}

#[test]
fn a_frame_is_taken_once() {
    let mut w = world();
    let frame = w.ada.seal_typing(G, true).unwrap();
    assert_eq!(w.bo.open_typing(G, &frame).unwrap(), opened(ADA, true));
    assert_eq!(w.bo.open_typing(G, &frame).unwrap(), None, "a replay");
    // The same words sealed again under a fresh nonce carry the same stamp.
    let renonced = rewrite(&w.bo, &frame, |_| {});
    assert_eq!(w.bo.open_typing(G, &renonced).unwrap(), None);
    // Two frames in the same millisecond carry two stamps, and both count.
    let a = w.ada.seal_typing(G, true).unwrap();
    let b = w.ada.seal_typing(G, true).unwrap();
    assert_eq!(w.bo.open_typing(G, &a).unwrap(), opened(ADA, true));
    assert_eq!(w.bo.open_typing(G, &b).unwrap(), opened(ADA, true));
}

#[test]
fn a_frame_from_outside_two_minutes_is_dropped() {
    let mut w = world();
    let old = w.ada.seal_typing(G, true).unwrap();
    advance_ms(120_001);
    assert_eq!(w.bo.open_typing(G, &old).unwrap(), None, "too old");
    let fresh = w.ada.seal_typing(G, true).unwrap();
    assert_eq!(w.cy.open_typing(G, &fresh).unwrap(), opened(ADA, true));

    let ahead = w.ada.seal_typing(G, true).unwrap();
    step_wall_ms(-120_001);
    assert_eq!(w.bo.open_typing(G, &ahead).unwrap(), None, "too far ahead");
}

#[test]
fn a_frame_does_not_cross_groups_or_epochs() {
    let mut w = world();
    // Bo holds both groups: a frame for one does not open in the other.
    let frame = w.ada.seal_typing(OTHER, true).unwrap();
    assert_eq!(w.bo.open_typing(G, &frame).unwrap(), None);
    assert_eq!(w.bo.open_typing(OTHER, &frame).unwrap(), opened(ADA, true));

    // A frame from the epoch before is dropped once the group has moved on.
    let before = w.ada.seal_typing(G, true).unwrap();
    let update = w.cy.self_update(G).unwrap();
    w.cy.merge_pending_commit(G).unwrap();
    for c in [&mut w.ada, &mut w.ada_laptop, &mut w.bo] {
        c.process_commit(G, &update.commit).unwrap();
    }
    assert_eq!(w.bo.open_typing(G, &before).unwrap(), None);
    let after = w.ada.seal_typing(G, true).unwrap();
    assert_eq!(w.bo.open_typing(G, &after).unwrap(), opened(ADA, true));
}

#[test]
fn an_unsigned_frame_is_dropped() {
    let mut w = world();
    // No `g`, no `s`: dropped whoever it names, its sender included.
    let unsigned = |c: &Client, actor: &str| {
        let words = TypingFrame {
            actor_id: actor.to_owned(),
            typing: true,
            stamp_ms: None,
            signature: None,
        };
        seal_typing_wire(
            &key(c, G),
            &[3u8; TYPING_NONCE_BYTES],
            &encode_typing(&words),
        )
        .unwrap()
    };
    let own = unsigned(&w.ada, ADA);
    assert_eq!(own.len(), TYPING_NONCE_BYTES + TYPING_BLOCK + 16);
    assert_eq!(w.bo.open_typing(G, &own).unwrap(), None);
    let forged = unsigned(&w.cy, ADA);
    assert_eq!(w.bo.open_typing(G, &forged).unwrap(), None);
    // A signed frame from the same sender still opens.
    let signed = w.ada.seal_typing(G, true).unwrap();
    assert_eq!(w.bo.open_typing(G, &signed).unwrap(), opened(ADA, true));
}
