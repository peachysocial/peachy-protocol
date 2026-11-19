// SPDX-License-Identifier: MIT
//! A DEVICE BACK AFTER A LONG ABSENCE DRAINS ITS MAILBOX IN ORDER AND ENDS
//! AT THE HEAD (docs/delivery.md §The mailbox).
//!
//! A user's iPhone was away about 54 hours while a community's own group and
//! its Chat group churned: back-to-back commits in both groups by one
//! member, a device re-seated after a seat ask, a person added and removed,
//! a rename, and messages from every member, sealed by the epoch. Its drain
//! then found most of what it was owed unreadable. This replays that churn
//! through the core alone: every envelope the away device was owed, in the
//! order the mailbox hands them out, opened and applied as the drains do.
//! Every member is this build, which refuses a lapsed sender, a second leaf
//! and a re-keyed reseat. If the core lost the
//! away device's place, it shows here; if it does not, the loss is in a
//! client's drain, not the protocol.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use peachy_mls_core::envelope::{
    ENVELOPE_KIND_COMMIT, ENVELOPE_KIND_MESSAGE, ENVELOPE_VERSION_EPOCH,
};
use peachy_mls_core::{Client, Incoming};
use support::{advance_ms, client, issuer, RemoveLeaf, HOUR};

const COMMUNITY: &[u8] = b"0c1d2e3f-4a5b-4c6d-8e7f-a0b1c2d3e4f5";
const CHAT: &[u8] = b"1d2e3f4a-5b6c-4d7e-9f80-b1c2d3e4f5a6";
const GROUPS: [&[u8]; 2] = [COMMUNITY, CHAT];

/// Who is in the room: the indexes into `Room::members`.
const MAC: usize = 0;
const WEB: usize = 1;
const ANDROID: usize = 2;
const IPAD: usize = 3;
const OLD: usize = 4;
const PHONE: usize = 5;

struct Room {
    members: Vec<Option<Client>>,
    /// Everything the away phone was owed, in mailbox order.
    mailbox: Vec<Vec<u8>>,
    /// Messages sent after the phone left, by text.
    sent: Vec<Vec<u8>>,
    texts: u32,
}

impl Room {
    fn m(&mut self, i: usize) -> &mut Client {
        self.members[i].as_mut().expect("seated")
    }

    /// `by` commits `bundle` (already staged): sealed BEFORE the merge, as
    /// the clients seal a commit for SubmitCommit, then merged; every online
    /// member applies it, and the away phone is owed it.
    fn land(&mut self, by: usize, group: &[u8], bundle: &peachy_mls_core::CommitBundle) {
        let wrapped = self
            .m(by)
            .seal_envelope(group, ENVELOPE_KIND_COMMIT, &bundle.commit)
            .unwrap();
        self.m(by).merge_pending_commit(group).unwrap();
        for i in 0..self.members.len() {
            if i == by || i == PHONE {
                continue;
            }
            let Some(member) = self.members[i].as_mut() else {
                continue;
            };
            if !member.group_ids().iter().any(|g| g == group) {
                continue;
            }
            let opened = member
                .open_envelope(&wrapped)
                .unwrap()
                .unwrap_or_else(|| panic!("member {i} opens the commit"));
            member.process_commit(group, &opened.inner).unwrap();
        }
        self.mailbox.push(wrapped);
    }

    fn say(&mut self, by: usize, group: &[u8]) {
        self.texts += 1;
        let text = format!("message {} from {by}", self.texts).into_bytes();
        let m = self.m(by).encrypt(group, &text).unwrap();
        let e = self
            .m(by)
            .seal_envelope(group, ENVELOPE_KIND_MESSAGE, &m)
            .unwrap();
        for i in 0..self.members.len() {
            if i == by || i == PHONE {
                continue;
            }
            let Some(member) = self.members[i].as_mut() else {
                continue;
            };
            if !member.group_ids().iter().any(|g| g == group) {
                continue;
            }
            let opened = member
                .open_envelope(&e)
                .unwrap()
                .expect("a member opens it");
            member.process_message(group, &opened.inner).unwrap();
        }
        self.mailbox.push(e);
        self.sent.push(text);
    }

    fn self_update(&mut self, by: usize, group: &[u8]) {
        let b = self.m(by).self_update(group).unwrap();
        self.land(by, group, &b);
    }
}

fn founded() -> Room {
    let s = issuer();
    let mut members: Vec<Option<Client>> = vec![
        Some(client(&s, 1, "actor-mac", "device-mac")),
        Some(client(&s, 2, "actor-web", "device-web")),
        Some(client(&s, 3, "actor-android", "device-android")),
        Some(client(&s, 4, "actor-phone", "device-ipad")),
        Some(client(&s, 5, "actor-old", "device-old")),
        Some(client(&s, 6, "actor-phone", "device-phone")),
    ];
    for group in GROUPS {
        members[MAC].as_mut().unwrap().create_group(group).unwrap();
        for joiner in [WEB, ANDROID, IPAD, OLD, PHONE] {
            let kp = members[joiner]
                .as_ref()
                .unwrap()
                .generate_key_package()
                .unwrap();
            let b = members[MAC]
                .as_mut()
                .unwrap()
                .add_member(group, &kp)
                .unwrap();
            members[MAC]
                .as_mut()
                .unwrap()
                .merge_pending_commit(group)
                .unwrap();
            for i in [WEB, ANDROID, IPAD, OLD, PHONE] {
                if i == joiner {
                    break;
                }
                members[i]
                    .as_mut()
                    .unwrap()
                    .process_commit(group, &b.commit)
                    .unwrap();
            }
            members[joiner]
                .as_mut()
                .unwrap()
                .join_from_welcome(&b.welcome.unwrap())
                .unwrap();
        }
    }
    Room {
        members,
        mailbox: Vec::new(),
        sent: Vec::new(),
        texts: 0,
    }
}

/// The churn of the user's 54 hours, in the shape the mailbox shows.
fn churn(room: &mut Room, seed: u64) {
    let s = issuer();
    let mut rng = seed;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for hour in 0..54u64 {
        advance_ms(u64::try_from(HOUR).unwrap() * 1000);
        let group = GROUPS[usize::try_from(next() % 2).unwrap()];
        let speaker = [MAC, WEB, ANDROID, IPAD, OLD][usize::try_from(next() % 5).unwrap()];
        room.say(speaker, group);
        match hour {
            // One member's back-to-back commits in both groups (11-11 02:32:49
            // and :50): a rotation in each.
            9 | 31 => {
                room.self_update(WEB, COMMUNITY);
                room.say(WEB, COMMUNITY);
                room.self_update(WEB, CHAT);
            }
            // A person added to both groups, and later removed.
            12 => {
                for group in GROUPS {
                    let newcomer = room.members.len();
                    if group == COMMUNITY {
                        room.members
                            .push(Some(client(&s, 7, "actor-new", "device-new")));
                    }
                    let joiner = if group == COMMUNITY {
                        newcomer
                    } else {
                        newcomer - 1
                    };
                    let kp = room.m(joiner).generate_key_package().unwrap();
                    let b = room.m(MAC).add_member(group, &kp).unwrap();
                    let welcome = b.welcome.clone().unwrap();
                    // The newcomer is not in the group yet: `land` skips it.
                    room.land(MAC, group, &b);
                    room.m(joiner).join_from_welcome(&welcome).unwrap();
                }
            }
            40 => {
                for group in GROUPS {
                    let leaf = room.m(ANDROID).leaf_of_device(group, "device-new").unwrap();
                    let b = room.m(ANDROID).remove_leaf(group, leaf).unwrap();
                    room.land(ANDROID, group, &b);
                }
                room.members[6] = None;
            }
            // The iPad lost its state and asked back in: re-seated in place
            // (same device key) in both groups, back to back.
            20 => {
                let mut fresh = client(&s, 4, "actor-phone", "device-ipad");
                // The old iPad copy is gone: it applies nothing more.
                room.members[IPAD] = None;
                let mut welcomes = Vec::new();
                for group in GROUPS {
                    let kp = fresh.generate_key_package().unwrap();
                    let leaf = room.m(MAC).leaf_of_device(group, "device-ipad").unwrap();
                    let b = room.m(MAC).replace_member(group, leaf, &kp).unwrap();
                    welcomes.push(b.welcome.clone().unwrap());
                    room.land(MAC, group, &b);
                }
                for w in welcomes {
                    fresh.join_from_welcome(&w).unwrap();
                }
                room.members[IPAD] = Some(fresh);
            }
            // A rename of the Chat group.
            46 => {
                let b = room
                    .m(MAC)
                    .set_group_meta(CHAT, b"{\"n\":\"Chat\"}")
                    .unwrap();
                room.land(MAC, CHAT, &b);
            }
            // Rotations by others, one group at a time.
            h if h % 7 == 3 => {
                let by = [MAC, ANDROID, IPAD][usize::try_from(next() % 3).unwrap()];
                let group = GROUPS[usize::try_from(next() % 2).unwrap()];
                room.self_update(by, group);
            }
            _ => {}
        }
    }
}

/// The away phone drains: each envelope opened against every group it holds
/// and put through the door its kind names, in mailbox order.
fn drain(room: &mut Room) -> (Vec<Vec<u8>>, Vec<String>) {
    let mut read = Vec::new();
    let mut failures = Vec::new();
    let mailbox = std::mem::take(&mut room.mailbox);
    let phone = room.members[PHONE].as_mut().unwrap();
    for (n, envelope) in mailbox.iter().enumerate() {
        let Some(opened) = phone.open_envelope(envelope).unwrap() else {
            failures.push(format!("#{n} (v{}) opens against no group", envelope[0]));
            continue;
        };
        let group = opened.group_id.clone();
        if opened.kind == ENVELOPE_KIND_COMMIT {
            if let Err(err) = phone.process_commit(&group, &opened.inner) {
                failures.push(format!("#{n} commit (v{}): {err}", envelope[0]));
            }
            continue;
        }
        match phone.process_message(&group, &opened.inner) {
            Ok(Incoming::Application { plaintext, .. }) => read.push(plaintext),
            Ok(other) => failures.push(format!("#{n} message came as {other:?}")),
            Err(err) => failures.push(format!("#{n} message (v{}): {err}", envelope[0])),
        }
    }
    (read, failures)
}

fn replay(seed: u64) {
    let mut room = founded();
    churn(&mut room, seed);
    let mac_epochs: Vec<u64> = GROUPS
        .iter()
        .map(|g| room.m(MAC).epoch(g).unwrap())
        .collect();
    let versions: std::collections::BTreeSet<u8> = room.mailbox.iter().map(|e| e[0]).collect();
    assert_eq!(
        versions,
        [ENVELOPE_VERSION_EPOCH].into(),
        "sealed by the epoch"
    );
    let (read, failures) = drain(&mut room);
    assert!(failures.is_empty(), "seed {seed}: {failures:#?}");
    assert_eq!(read, room.sent, "every message read, in order");
    let phone_epochs: Vec<u64> = GROUPS
        .iter()
        .map(|g| room.m(PHONE).epoch(g).unwrap())
        .collect();
    assert_eq!(phone_epochs, mac_epochs, "the phone ends at the head");
}

#[test]
fn a_device_back_after_54_hours_of_churn_reads_everything() {
    replay(0x9e37_79b9_7f4a_7c15);
}
