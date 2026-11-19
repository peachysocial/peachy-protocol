// SPDX-License-Identifier: MIT
//! A group of somebody's own under a group id cannot shut a device out of
//! the real group (docs/delivery.md §Two seats under one group id).
//!
//! A group id is a name, not a secret: an ex-member, or any member, can found
//! a group of their own under it, at any epoch they like (a modified client
//! signs any epoch into its GroupInfo), and Welcome a device there. If such a
//! seat raised the device's epoch mark to that epoch, the device would refuse
//! every Welcome of the real group at or below it for good, forgotten or not:
//! out of the conversation until the real group committed past an epoch the
//! attacker chose.
//!
//! So the mark counts only epochs the group's head vouched for. A Welcome is
//! taken against the head (`join_from_welcome_at_head`): above it, or at it
//! under another send key, it is refused; below it, it is taken unconfirmed.
//! A copy is confirmed when it matches the head (`confirm_head`, a merge of
//! this device's own commit, a seat at the head), and only a confirmed copy's
//! epochs reach the mark or name a roster.
//!
//! `take` and `confirm` are how the apps take a Welcome from the mailbox and
//! what they do with every head they read.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolVersion, Welcome};
use peachy_mls_core::storage::namespace_prefix;
use peachy_mls_core::welcome_frame::{frame_welcome, unframe_welcome};
use peachy_mls_core::{Client, Error, Incoming, KvStore, MemoryKv, PeachyStorage};
use sha2::{Digest, Sha256};
use support::{client, client_on, head_of, issuer};
use tls_codec::{Deserialize as _, Serialize as _};

const G: &[u8] = b"4c2e8f10-7b3a-4d5e-9f6a-1b2c3d4e5f60";
const HUGE: u64 = 1 << 40;

/// Take a Welcome the way the apps do: read which group it is for, then
/// take it against that group's head.
fn take(c: &mut Client, welcome: &[u8], head: (u64, [u8; 32])) -> Result<Vec<u8>, Error> {
    let (group, _epoch) = c.welcome_group(welcome)?;
    assert_eq!(group, G);
    c.join_from_welcome_at_head(welcome, head.0, &head.1)
}

/// What the apps do with every head they read.
fn confirm(c: &mut Client, head: (u64, [u8; 32])) -> bool {
    c.confirm_head(G, head.0, &head.1).unwrap()
}

fn opens(reader: &mut Client, wire: &[u8], text: &[u8]) -> bool {
    matches!(
        reader.process_message(G, wire),
        Ok(Incoming::Application { plaintext, .. }) if plaintext == text
    )
}

fn bump(founder: &mut Client, times: usize) {
    for _ in 0..times {
        founder.self_update(G).unwrap();
        founder.merge_pending_commit(G).unwrap();
    }
}

/// A group under `G` founded by a client of `actor`'s, whose stored epoch is
/// then rewritten to `epoch`, as a modified client would simply write it.
/// Reopened from the same store, every later commit and Welcome it makes is
/// internally consistent at that epoch.
fn impostor_at_epoch(
    server: &peachy_mls_core::issuer::TestIssuer,
    tag: u8,
    actor: &str,
    device: &str,
    epoch: u64,
) -> Client {
    let kv = MemoryKv::new();
    {
        let storage = PeachyStorage::open(Box::new(kv.clone())).unwrap();
        let mut founder = client_on(server, tag, actor, device, storage);
        founder.create_group(G).unwrap();
    }
    let prefix = namespace_prefix(b"group_context");
    let entries = kv.scan(&prefix).unwrap();
    assert_eq!(entries.len(), 1, "one stored group context");
    for (key, value) in entries {
        let mut json: serde_json::Value = serde_json::from_slice(&value).unwrap();
        json["epoch"] = serde_json::json!(epoch);
        kv.put(&key, &serde_json::to_vec(&json).unwrap()).unwrap();
    }
    kv.flush().unwrap();
    let storage = PeachyStorage::open(Box::new(kv.clone())).unwrap();
    let reopened = client_on(server, tag, actor, device, storage);
    assert_eq!(reopened.epoch(G).unwrap(), epoch);
    reopened
}

/// Test 1: A member's impostor at an epoch it chose cannot lock a rejoining
/// device out. Mallory, in the roster Bo kept, answers his rejoin first from
/// a group of hers under G at epoch 2^40: above the head, refused at seat.
/// Ada's re-seat is taken, and Ada's next message opens for Bo.
#[test]
fn an_inflated_welcome_from_a_member_is_refused_and_the_real_reseat_is_taken() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut mal = client(&server, 3, "actor-mal", "device-mal");

    ada.create_group(G).unwrap();
    let add_bo = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    take(&mut bo, &add_bo.welcome.unwrap(), head_of(&ada, G)).unwrap();
    let add_mal = ada
        .add_member(G, &mal.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &add_mal.commit).unwrap();
    take(&mut mal, &add_mal.welcome.unwrap(), head_of(&ada, G)).unwrap();

    // Bo falls off the ratchet and forgets the group to ask back in.
    bo.forget_group(G).unwrap();

    let mut imp = impostor_at_epoch(&server, 3, "actor-mal", "device-mal", HUGE);
    let fake = imp
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    imp.merge_pending_commit(G).unwrap();
    let squat = take(&mut bo, &fake.welcome.unwrap(), head_of(&ada, G));
    assert!(matches!(squat, Err(Error::AlreadyAMember)), "{squat:?}");
    assert!(
        matches!(bo.epoch(G), Err(Error::NoSuchGroup)),
        "nothing seated"
    );

    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    let reseat = ada
        .replace_member(G, bo_leaf, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut bo, &reseat.welcome.unwrap(), head_of(&ada, G)).unwrap(),
        G
    );
    assert_eq!(head_of(&bo, G), head_of(&ada, G));
    let wire = ada.encrypt(G, b"welcome back").unwrap();
    assert!(opens(&mut bo, &wire, b"welcome back"));
}

/// Test 2: A newly linked device. Mallory's squat at 2^40 is refused; a squat
/// below the head (Eve's, from a group she pushed 64 epochs on) is taken
/// unconfirmed and then gives way to the real Welcome at the head. Either
/// way, what the laptop seals in G next opens for Ada and for no squatter.
#[test]
fn a_new_own_device_takes_the_real_group_over_any_squat() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut eve = client(&server, 5, "actor-eve", "device-eve");
    let mut laptop = client(&server, 4, "actor-ada", "device-ada-laptop");
    ada.create_group(G).unwrap();
    bump(&mut ada, 70);

    // Above the head.
    let mut imp = impostor_at_epoch(&server, 3, "actor-mal", "device-mal", HUGE);
    let fake = imp
        .add_member(G, &laptop.generate_key_package().unwrap())
        .unwrap();
    imp.merge_pending_commit(G).unwrap();
    let squat = take(&mut laptop, &fake.welcome.unwrap(), head_of(&ada, G));
    assert!(matches!(squat, Err(Error::AlreadyAMember)), "{squat:?}");
    assert!(matches!(laptop.epoch(G), Err(Error::NoSuchGroup)));

    // Below the head: taken, unconfirmed.
    eve.create_group(G).unwrap();
    bump(&mut eve, 64);
    let fake = eve
        .add_member(G, &laptop.generate_key_package().unwrap())
        .unwrap();
    eve.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut laptop, &fake.welcome.unwrap(), head_of(&ada, G)).unwrap(),
        G
    );
    assert!(
        !confirm(&mut laptop, head_of(&ada, G)),
        "a squat is never the head"
    );

    // The real seat, from Ada's own phone, at the head: it replaces the squat.
    let real = ada
        .add_member(G, &laptop.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut laptop, &real.welcome.unwrap(), head_of(&ada, G)).unwrap(),
        G
    );
    assert_eq!(head_of(&laptop, G), head_of(&ada, G));
    assert!(confirm(&mut laptop, head_of(&ada, G)));

    let text = b"the new door code is 4471";
    let wire = laptop.encrypt(G, text).unwrap();
    assert!(opens(&mut ada, &wire, text), "ada reads the laptop");
    assert!(!opens(&mut eve, &wire, text), "eve does not");
    assert!(!opens(&mut imp, &wire, text), "nor does mallory");
}

/// Ada founds G and adds Eve, then removes her. Eve forgets her dead copy
/// and founds a group of her own under G, pushed 64 epochs on.
fn ex_member_squats(ada: &mut Client, eve: &mut Client) {
    ada.create_group(G).unwrap();
    let added = ada
        .add_member(G, &eve.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    take(eve, &added.welcome.unwrap(), head_of(ada, G)).unwrap();
    let leaf = ada.leaf_of_device(G, "device-eve").unwrap();
    let removal = ada.remove_leaf(G, leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    eve.process_commit(G, &removal.commit).unwrap();
    eve.forget_group(G).unwrap();
    eve.create_group(G).unwrap();
    bump(eve, 64);
}

/// Test 3: A device that was never in G. Eve's squat, far above the real
/// head, is refused at seat; Dan's person declines
/// whatever is left. Ada's first real add is taken, and every re-add after.
#[test]
fn a_declined_squat_leaves_the_real_add_to_be_taken() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut eve = client(&s, 3, "actor-eve", "device-eve");
    let mut dan = client(&s, 4, "actor-dan", "device-dan");
    ex_member_squats(&mut ada, &mut eve);

    let fake = eve
        .add_member(G, &dan.generate_key_package().unwrap())
        .unwrap();
    eve.merge_pending_commit(G).unwrap();
    let _ = take(&mut dan, &fake.welcome.unwrap(), head_of(&ada, G));
    // Dan declines it: whatever copy and roster there are go.
    if dan.epoch(G).is_ok() {
        dan.forget_group(G).unwrap();
    }
    dan.forget_remembered_roster(G).unwrap();

    for attempt in 0..5 {
        if attempt > 0 {
            dan.forget_group(G).unwrap();
            let leaf = ada.leaf_of_device(G, "device-dan").unwrap();
            ada.remove_leaf(G, leaf).unwrap();
            ada.merge_pending_commit(G).unwrap();
        }
        let real = ada
            .add_member(G, &dan.generate_key_package().unwrap())
            .unwrap();
        ada.merge_pending_commit(G).unwrap();
        let taken = take(&mut dan, &real.welcome.unwrap(), head_of(&ada, G));
        assert_eq!(taken.unwrap(), G, "attempt {attempt}");
        let wire = ada.encrypt(G, b"dan, are you there?").unwrap();
        assert!(
            opens(&mut dan, &wire, b"dan, are you there?"),
            "attempt {attempt}"
        );
    }
}

/// Test 4: A forget does not lock a newly linked device out. The laptop takes a
/// squat below the head and forgets it, holding nothing for G; the real
/// re-add is taken, also after the real group moved 32 epochs on, and so is
/// a second removal and re-add.
#[test]
fn a_forgotten_squat_does_not_lock_a_new_device_out() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut carol = client(&server, 5, "actor-carol", "device-carol-phone");
    let mut laptop = client(&server, 3, "actor-ada", "device-ada-laptop");
    ada.create_group(G).unwrap();
    bump(&mut ada, 70);

    carol.create_group(G).unwrap();
    bump(&mut carol, 64);
    let fake = carol
        .add_member(G, &laptop.generate_key_package().unwrap())
        .unwrap();
    carol.merge_pending_commit(G).unwrap();
    take(&mut laptop, &fake.welcome.unwrap(), head_of(&ada, G)).unwrap();
    let squatted = laptop.epoch(G).unwrap();
    // Carol pushes the copy on with commits the real group never saw.
    for _ in 0..8 {
        let c = carol.self_update(G).unwrap();
        carol.merge_pending_commit(G).unwrap();
        laptop.process_commit(G, &c.commit).unwrap();
    }
    assert!(laptop.epoch(G).unwrap() > ada.epoch(G).unwrap());
    assert!(!confirm(&mut laptop, head_of(&ada, G)));
    laptop.forget_group(G).unwrap();
    assert!(matches!(laptop.epoch(G), Err(Error::NoSuchGroup)));

    // Ada seats the laptop, after 32 more epochs.
    bump(&mut ada, 32);
    let real = ada
        .add_member(G, &laptop.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert!(ada.epoch(G).unwrap() > squatted);
    assert_eq!(
        take(&mut laptop, &real.welcome.unwrap(), head_of(&ada, G)).unwrap(),
        G
    );

    // Removed and re-added once more. The laptop now knew the real group, so
    // this Welcome is a rejoin, drawn against its roster.
    laptop.forget_group(G).unwrap();
    let leaf = ada.leaf_of_device(G, "device-ada-laptop").unwrap();
    ada.remove_leaf(G, leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let again = ada
        .add_member(G, &laptop.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut laptop, &again.welcome.unwrap(), head_of(&ada, G)).unwrap(),
        G
    );
    let wire = ada.encrypt(G, b"back in G").unwrap();
    assert!(opens(&mut laptop, &wire, b"back in G"));
}

/// Test 5: Commits the real group never took do not raise the mark. Eve seats
/// Dan below the head and then feeds him 100 commits of her own group; Dan
/// forgets the copy, and Ada's add at the next epoch is taken.
#[test]
fn off_head_commits_into_a_squat_raise_no_mark() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut eve = client(&s, 3, "actor-eve", "device-eve");
    let mut dan = client(&s, 4, "actor-dan", "device-dan");
    ada.create_group(G).unwrap();
    bump(&mut ada, 3);

    eve.create_group(G).unwrap();
    let fake = eve
        .add_member(G, &dan.generate_key_package().unwrap())
        .unwrap();
    eve.merge_pending_commit(G).unwrap();
    take(&mut dan, &fake.welcome.unwrap(), head_of(&ada, G)).unwrap();
    for _ in 0..100 {
        let c = eve.self_update(G).unwrap();
        eve.merge_pending_commit(G).unwrap();
        dan.process_commit(G, &c.commit).unwrap();
    }
    assert_eq!(dan.epoch(G).unwrap(), 101);
    assert!(
        !confirm(&mut dan, head_of(&ada, G)),
        "a copy above the head is a branch"
    );
    dan.forget_group(G).unwrap();

    let real = ada
        .add_member(G, &dan.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert_eq!(ada.epoch(G).unwrap(), 4);
    assert_eq!(
        take(&mut dan, &real.welcome.unwrap(), head_of(&ada, G)).unwrap(),
        G
    );
    let wire = ada.encrypt(G, b"hello dan").unwrap();
    assert!(opens(&mut dan, &wire, b"hello dan"));
}

/// Test 6: The honest head rescues a squatted invitee: the Welcome that
/// replaces Eve's copy is taken. It is still drawn, never passed over as a
/// first join: re-added by Ada, with Eve gone.
#[test]
fn the_head_rescues_a_squatted_invitee() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut eve = client(&s, 3, "actor-eve", "device-eve");
    let mut dan = client(&s, 4, "actor-dan", "device-dan");
    ada.create_group(G).unwrap();
    bump(&mut ada, 3);

    eve.create_group(G).unwrap();
    let fake = eve
        .add_member(G, &dan.generate_key_package().unwrap())
        .unwrap();
    eve.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut dan, &fake.welcome.unwrap(), head_of(&ada, G)).unwrap(),
        G
    );

    let real = ada
        .add_member(G, &dan.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut dan, &real.welcome.unwrap(), head_of(&ada, G)).unwrap(),
        G
    );
    let report = dan
        .take_rejoin_report(G)
        .unwrap()
        .expect("drawn, not a first join");
    assert_eq!(report.readded_by, "actor-ada");
    assert!(!report.readded_by_untrusted, "{report:?}");
    assert_eq!(report.departed_actors, vec!["actor-eve"]);
    let wire = dan.encrypt(G, b"hi").unwrap();
    assert!(opens(&mut ada, &wire, b"hi"), "dan now sits with ada");
    assert!(!opens(&mut eve, &wire, b"hi"));
}

type LastResortSetup = (Client, Client, Client, MemoryKv, Vec<u8>, (u64, [u8; 32]));

/// Ada adds Eve, then Bo through Bo's LAST-RESORT key package. Bo's store is
/// a MemoryKv the test reads. Returns the clients, Bo's store, the Welcome,
/// and the head the server recorded for the epoch it seals.
fn last_resort_setup() -> LastResortSetup {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let kv = MemoryKv::new();
    let mut bo = client_on(
        &server,
        2,
        "actor-bo",
        "device-bo",
        PeachyStorage::open(Box::new(kv.clone())).unwrap(),
    );
    let mut eve = client(&server, 3, "actor-eve", "device-eve");
    ada.create_group(G).unwrap();
    let add_eve = ada
        .add_member(G, &eve.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    take(&mut eve, &add_eve.welcome.unwrap(), head_of(&ada, G)).unwrap();

    let (last_resort, _) = bo.generate_last_resort_key_package_with_ref().unwrap();
    let add_bo = ada.add_member(G, &last_resort).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let welcome = add_bo.welcome.unwrap();
    take(&mut bo, &welcome, head_of(&ada, G)).unwrap();
    eve.process_commit(G, &add_bo.commit).unwrap();
    let old_head = head_of(&ada, G);
    (ada, bo, eve, kv, welcome, old_head)
}

/// Ada removes Eve, then rotates; Bo applies both. Eve never applies hers.
fn remove_eve(ada: &mut Client, bo: &mut Client) {
    let leaf = ada.leaf_of_device(G, "device-eve").unwrap();
    let removal = ada.remove_leaf(G, leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
    let rotate = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &rotate.commit).unwrap();
}

/// The same Welcome with its unsigned `secrets` list rewritten (Bo's entry
/// listed twice), as the delivery service could hand it back: it still opens
/// for Bo, and its bytes differ.
fn with_secrets_rewritten(welcome: &[u8]) -> Vec<u8> {
    // The MLS Welcome inside the frame, rewritten and framed again.
    let welcome = unframe_welcome(welcome).unwrap();
    let message = MlsMessageIn::tls_deserialize_exact(welcome).unwrap();
    let MlsMessageBodyIn::Welcome(parsed) = message.extract() else {
        panic!("a Welcome");
    };
    let mut json = serde_json::to_value(&parsed).unwrap();
    let secrets = json["secrets"].as_array_mut().unwrap();
    let first = secrets[0].clone();
    secrets.insert(0, first);
    let rewritten: Welcome = serde_json::from_value(json).unwrap();
    let out = MlsMessageOut::from_welcome(rewritten, ProtocolVersion::Mls10);
    let bytes = out.tls_serialize_detached().unwrap();
    assert_ne!(bytes, welcome);
    frame_welcome(&bytes, 0).unwrap()
}

/// Test 7: The last-resort Welcome replay stays closed through the head
/// door. The server hands an active member, and a removed one, the same
/// last-resort Welcome again, as it was and with its `secrets` list rewritten, and
/// names the head it recorded for that old epoch: refused every time, nothing
/// rolls back, and removed Eve reads nothing. The seat is remembered under a
/// key fixed by what the Welcome opened to, not by its bytes.
#[test]
fn a_replayed_last_resort_welcome_is_refused_under_a_lying_head() {
    let (mut ada, mut bo, mut eve, kv, welcome, old_head) = last_resort_setup();
    remove_eve(&mut ada, &mut bo);
    let live = bo.epoch(G).unwrap();
    assert!(live > old_head.0);

    let rewritten = with_secrets_rewritten(&welcome);
    for replay in [&welcome, &rewritten] {
        let refused = take(&mut bo, replay, old_head);
        assert!(matches!(refused, Err(Error::AlreadyAMember)), "{refused:?}");
        assert_eq!(bo.epoch(G).unwrap(), live);
    }
    let text = b"the gate code changed after eve left";
    let wire = bo.encrypt(G, text).unwrap();
    assert!(opens(&mut ada, &wire, text));
    assert!(!opens(&mut eve, &wire, text), "removed eve reads nothing");

    // The record of the taking: one key, neither replay's digest.
    let taken = kv.scan(&namespace_prefix(b"welcome_taken")).unwrap();
    assert_eq!(
        taken.len(),
        1,
        "one seat taken through the last-resort package"
    );
    let prefix_len = namespace_prefix(b"welcome_taken").len();
    let key = &taken[0].0[prefix_len..];
    assert_ne!(
        key,
        Sha256::digest(&welcome).as_slice(),
        "not the bytes the server can change"
    );
    assert_ne!(key, Sha256::digest(&rewritten).as_slice());

    // Removed, and forgotten: the replays reseat nobody.
    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    let removal = ada.remove_leaf(G, bo_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
    assert!(!bo.is_active(G).unwrap());
    for replay in [&welcome, &rewritten] {
        assert!(matches!(
            take(&mut bo, replay, old_head),
            Err(Error::AlreadyAMember)
        ));
        assert!(matches!(
            bo.join_from_welcome(replay),
            Err(Error::AlreadyAMember)
        ));
        assert!(!bo.is_active(G).unwrap());
    }
    bo.forget_group(G).unwrap();
    for replay in [&welcome, &rewritten] {
        assert!(matches!(
            take(&mut bo, replay, old_head),
            Err(Error::AlreadyAMember)
        ));
        assert!(bo.epoch(G).is_err(), "nothing was seated");
    }
}

/// Test 8: Only a confirmed copy's epochs reach the mark. Bo takes Eve's squat
/// below the head and she walks it on to epoch 6; he forgets it, and Ada's
/// add at epoch 6 is taken. That seat is at the head, so it is confirmed:
/// the group moves on 5 epochs, Bo forgets it, and a Welcome at the epoch he
/// reached is refused.
#[test]
fn only_a_confirmed_copys_epochs_reach_the_mark() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut eve = client(&server, 3, "actor-eve", "device-eve");
    let mut carol = client(&server, 5, "actor-carol", "device-carol");
    ada.create_group(G).unwrap();
    bump(&mut ada, 3);

    eve.create_group(G).unwrap();
    let fake = eve
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    eve.merge_pending_commit(G).unwrap();
    take(&mut bo, &fake.welcome.unwrap(), head_of(&ada, G)).unwrap();
    for _ in 0..5 {
        let c = eve.self_update(G).unwrap();
        eve.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &c.commit).unwrap();
    }
    assert_eq!(bo.epoch(G).unwrap(), 6);
    bo.forget_group(G).unwrap();

    bump(&mut ada, 2);
    let add = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert_eq!(ada.epoch(G).unwrap(), 6);
    assert_eq!(
        take(&mut bo, &add.welcome.unwrap(), head_of(&ada, G)).unwrap(),
        G
    );
    assert!(confirm(&mut bo, head_of(&ada, G)));

    for _ in 0..5 {
        let c = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &c.commit).unwrap();
    }
    let reached = bo.epoch(G).unwrap();
    bo.forget_group(G).unwrap();

    carol.create_group(G).unwrap();
    bump(&mut carol, (reached - 1) as usize);
    let at_mark = carol
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    carol.merge_pending_commit(G).unwrap();
    assert_eq!(carol.epoch(G).unwrap(), reached);
    assert!(matches!(
        bo.join_from_welcome(&at_mark.welcome.unwrap()),
        Err(Error::AlreadyAMember)
    ));
    assert!(bo.epoch(G).is_err());
}
