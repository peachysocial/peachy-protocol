// SPDX-License-Identifier: MIT
//! A self-note is believed only from a live device of the account, signed by
//! that device's own key, within its window, and once.
//!
//! The attack this holds shut: a device that was approved once keeps the
//! account key after it is removed. Under the older unsigned format
//! (version 1, which no build opens now) that key alone made notes the
//! person's other devices could not tell from their own: a forged history hand-off pointing
//! at an object the attacker chose, a read position, a reaction. The receiver
//! here models what every client does (docs/sealed-messages.md
//! §Self-notes): ask the note who sent it, look that device up in its own
//! device list, open it against that device's key, and drop an id it has
//! already acted on.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use peachy_mls_core::{
    account_store::note_seal_with, generate_account_key, note_open_signed, note_seal_signed,
    note_sender, signing_key_public_key, NOTE_MAX_AGE_MS,
};

const NOW: i64 = 1_790_000_000_000;
const PHONE: &str = "device-ada-phone";
const LAPTOP: &str = "device-ada-laptop";
const PHONE_SEED: [u8; 32] = [0x01; 32];
const LAPTOP_SEED: [u8; 32] = [0x02; 32];
const THIEF_SEED: [u8; 32] = [0x09; 32];

/// The receiving device: its account key, the device list it holds (only
/// live, approved, certified rows), and the note ids it has acted on.
struct Receiver {
    account_key: [u8; 32],
    devices: BTreeMap<&'static str, [u8; 32]>,
    seen: BTreeSet<[u8; 16]>,
}

impl Receiver {
    fn take(&mut self, id: [u8; 16], value: &[u8], now: i64) -> Result<Vec<u8>, String> {
        if self.seen.contains(&id) {
            return Err("already acted on".into());
        }
        let sender = note_sender(&self.account_key, &id, value).map_err(|e| e.to_string())?;
        let key = self
            .devices
            .get(sender.as_str())
            .ok_or_else(|| format!("{sender} is not a live device of this account"))?;
        let plaintext = note_open_signed(&self.account_key, &id, value, &sender, key, now)
            .map_err(|e| e.to_string())?;
        self.seen.insert(id);
        Ok(plaintext)
    }
}

fn public(seed: &[u8; 32]) -> [u8; 32] {
    signing_key_public_key(seed).expect("a public half")
}

const FORGED_HANDOFF: &[u8] =
    br#"{"peachy":"transfer","v":1,"f":3,"ptr":{"o":"sealed/attacker-object","k":"AAAA"}}"#;

#[test]
fn a_removed_device_holding_the_account_key_cannot_send_a_note_the_others_act_on() {
    let account_key = generate_account_key().expect("account key");
    let retained = account_key; // what the removed laptop kept

    // Ada removed the laptop: her phone's list no longer holds it.
    let mut phone_view = Receiver {
        account_key,
        devices: BTreeMap::from([(PHONE, public(&PHONE_SEED))]),
        seen: BTreeSet::new(),
    };

    // 1. The old format: the account key alone makes a note. A receiver that
    //    asks who sent it is told nobody, and does not act.
    let id = [0x42_u8; 16];
    let unsigned = note_seal_with(&retained, &id, FORGED_HANDOFF, &[0; 12]).expect("seals");
    let refused = phone_view
        .take(id, &unsigned, NOW)
        .expect_err("names nobody");
    assert!(refused.contains("unsigned"), "{refused}");

    // 2. Signed as itself, with the key it kept: it is not on the list.
    let as_itself =
        note_seal_signed(&retained, &id, FORGED_HANDOFF, LAPTOP, NOW, &LAPTOP_SEED).expect("seals");
    let refused = phone_view.take(id, &as_itself, NOW).expect_err("removed");
    assert!(refused.contains("not a live device"), "{refused}");

    // 3. Signed as the phone, with a key it made up: the phone's key on the
    //    list does not verify it.
    let as_phone =
        note_seal_signed(&retained, &id, FORGED_HANDOFF, PHONE, NOW, &THIEF_SEED).expect("seals");
    let refused = phone_view
        .take(id, &as_phone, NOW)
        .expect_err("not the phone's key");
    assert!(refused.contains("does not verify"), "{refused}");

    assert!(phone_view.seen.is_empty(), "nothing was acted on");
}

#[test]
fn a_genuine_note_acts_once_and_not_after_its_window() {
    let account_key = generate_account_key().expect("account key");
    let mut laptop_view = Receiver {
        account_key,
        devices: BTreeMap::from([(PHONE, public(&PHONE_SEED)), (LAPTOP, public(&LAPTOP_SEED))]),
        seen: BTreeSet::new(),
    };
    let read = br#"{"peachy":"read","v":1,"g":"g","m":"m","at":1790000000000}"#;

    let id = [0x07_u8; 16];
    let note = note_seal_signed(&account_key, &id, read, PHONE, NOW, &PHONE_SEED).expect("seals");
    assert_eq!(laptop_view.take(id, &note, NOW + 1).expect("acts"), read);
    // The server delivers it again: the id was acted on.
    let refused = laptop_view.take(id, &note, NOW + 2).expect_err("replayed");
    assert!(refused.contains("already acted on"), "{refused}");

    // A note the server held back past the window is refused even by a device
    // that forgot which ids it saw (a fresh install, a cleared table).
    let held = [0x08_u8; 16];
    let late = note_seal_signed(&account_key, &held, read, PHONE, NOW, &PHONE_SEED).expect("seals");
    let mut forgetful = Receiver {
        seen: BTreeSet::new(),
        ..laptop_view
    };
    let refused = forgetful
        .take(held, &late, NOW + NOTE_MAX_AGE_MS + 1)
        .expect_err("stale");
    assert!(refused.contains("stale"), "{refused}");
}

#[test]
fn a_note_moved_to_another_id_does_not_open() {
    let account_key = generate_account_key().expect("account key");
    let note =
        note_seal_signed(&account_key, &[0x01; 16], b"{}", PHONE, NOW, &PHONE_SEED).expect("seals");
    // A server that re-files a note under a fresh id to dodge the dedup table.
    assert!(note_sender(&account_key, &[0x02; 16], &note).is_err());
    assert!(note_open_signed(
        &account_key,
        &[0x02; 16],
        &note,
        PHONE,
        &public(&PHONE_SEED),
        NOW
    )
    .is_err());
}
