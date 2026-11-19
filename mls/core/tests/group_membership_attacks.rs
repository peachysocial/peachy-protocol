// SPDX-License-Identifier: MIT
//! What a person outside a group's current membership can still do to it,
//! with the group id and the keys of epochs they were in, and what each
//! member's device now does about it.
//!
//! - A removed member seals at an epoch it was in: refused as
//!   [`Error::NotFromAMember`], which a client answers with silence
//!   (docs/delivery.md §A message that will not open).
//! - Anyone with the group id rewrites a message's framing to read as a commit
//!   at the members' epoch: it does not open, so it strands nobody
//!   (`commit_strands`); only a commit that opened and verified does.
//! - A removed member founds a group of its own under the same id and seats a
//!   member's new device in it first: taken against the group's head
//!   (`join_from_welcome_at_head`), a squat above the head is refused and one
//!   below it gives way to the real Welcome at the head; taken without one,
//!   the real Welcome is refused as `AlreadyAMember`, but kept, and the head
//!   decides which seat the device keeps (`join_contested_welcome`).
//! - The delivery service hands the same signed seat ask over twice: a device
//!   takes it in once (`first_sight_of_join_request`).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::envelope::{
    open_envelope_among, seal_group_id_envelope, ENVELOPE_KIND_MESSAGE,
};
use peachy_mls_core::hint::CONTENT_HINT_RESENDABLE;
use peachy_mls_core::{Client, Error, Incoming, JoinRequestVerdict, SEND_KEY_LABEL};
use sha2::{Digest, Sha256};
use support::{client, issuer, past_the_mark};

const G: &[u8] = b"0f8e2a1c-5b7d-4e9a-8c3f-2d1b6a9e7c40";
const ADA: &str = "5b0f5a52-8a55-4a5b-9d59-1b9a7a3f0c11";
const BO: &str = "0f3c6d2e-1111-4222-8333-944455556666";
const CY: &str = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
const ADA_D: &str = "11111111-aaaa-4aaa-8aaa-111111111111";
const BO_D: &str = "22222222-bbbb-4bbb-8bbb-222222222222";
const CY_D: &str = "33333333-cccc-4ccc-8ccc-333333333333";

/// Ada founds G and seats Bo, then Cy.
fn trio() -> (Client, Client, Client) {
    let s = issuer();
    let mut ada = client(&s, 1, ADA, ADA_D);
    let mut bo = client(&s, 2, BO, BO_D);
    let mut cy = client(&s, 3, CY, CY_D);
    ada.create_group(G).unwrap();
    let kp = bo.generate_key_package().unwrap();
    let added = ada.add_member(G, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.join_from_welcome(&added.welcome.unwrap()).unwrap();
    let kp = cy.generate_key_package().unwrap();
    let added = ada.add_member(G, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &added.commit).unwrap();
    cy.join_from_welcome(&added.welcome.unwrap()).unwrap();
    (ada, bo, cy)
}

/// Ada removes Cy; Bo applies it. Cy never does.
fn remove_cy(ada: &mut Client, bo: &mut Client) {
    let cy_leaf = ada.leaf_of_device(G, CY_D).unwrap();
    let removal = ada.remove_leaf(G, cy_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
}

/// The head the delivery service holds for a group, as a member derives it:
/// the epoch, and the SHA-256 of that epoch's send key.
fn head_of(member: &Client) -> (u64, Vec<u8>) {
    let key = member.export_secret(G, SEND_KEY_LABEL, G, 32).unwrap();
    (member.epoch(G).unwrap(), Sha256::digest(key).to_vec())
}

#[test]
fn a_removed_member_sealing_at_its_old_epoch_is_refused_as_not_from_a_member() {
    let (mut ada, mut bo, mut cy) = trio();
    remove_cy(&mut ada, &mut bo);
    for _ in 0..3 {
        // Cy keeps the group id and her last epoch's keys: the envelope opens
        // as G's and the message decrypts at that epoch.
        let sealed = cy
            .encrypt_with_hint(G, b"anything", CONTENT_HINT_RESENDABLE)
            .unwrap();
        let env = seal_group_id_envelope(G, ENVELOPE_KIND_MESSAGE, &sealed).unwrap();
        let opened = open_envelope_among([G], &env).unwrap().expect("opens as G");
        let refused = bo.process_message(G, &opened.inner);
        assert!(
            matches!(refused, Err(Error::NotFromAMember(_))),
            "a removed member's message was refused as {refused:?}, which a client shows as a loss"
        );
        assert_eq!(refused.unwrap_err().code(), 17);
    }
    // Bo is still healthy afterwards.
    let ok = ada.encrypt(G, b"still works").unwrap();
    assert!(matches!(
        bo.process_message(G, &ok).unwrap(),
        Incoming::Application { .. }
    ));
}

#[test]
fn a_current_members_message_from_a_past_epoch_still_reads() {
    let (mut ada, mut bo, _cy) = trio();
    // Sealed before a commit, delivered after it: the epoch is past, the
    // sender is still in the tree.
    let early = ada.encrypt(G, b"from before the self-update").unwrap();
    let update = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &update.commit).unwrap();
    match bo
        .process_message(G, &early)
        .expect("a member's late message reads")
    {
        Incoming::Application {
            plaintext, sender, ..
        } => {
            assert_eq!(plaintext, b"from before the self-update");
            assert_eq!(sender.actor_id, ADA);
        }
        other => panic!("expected an application message, got {other:?}"),
    }
}

#[test]
fn a_member_removed_after_sealing_is_silent_too() {
    // Nothing in a message says whether it was sealed before or after its
    // sender's removal, so one sealed honestly and delivered late is refused
    // the same way. The receiver cannot tell the two apart.
    let (mut ada, mut bo, mut cy) = trio();
    let late = cy.encrypt(G, b"sent before the removal").unwrap();
    remove_cy(&mut ada, &mut bo);
    assert!(matches!(
        bo.process_message(G, &late),
        Err(Error::NotFromAMember(_))
    ));
    // The refusal came after the message opened, and spent nothing: handed
    // over again it is refused the same way, not as a duplicate (the record
    // kept it) nor as a spent key (the ratchet kept the spend).
    assert!(matches!(
        bo.process_message(G, &late),
        Err(Error::NotFromAMember(_))
    ));
}

#[test]
fn framing_rewritten_to_read_as_a_commit_strands_nobody() {
    let (mut ada, mut bo, mut cy) = trio();
    remove_cy(&mut ada, &mut bo);
    for _ in 0..3 {
        let c = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &c.commit).unwrap();
    }
    let now = bo.epoch(G).unwrap();
    // Cy rewrites the clear PrivateMessage framing of a message of hers:
    // epoch := the members' epoch, content type := commit.
    let mut forged = cy.encrypt(G, b"x").unwrap();
    assert_eq!(forged[4] as usize, G.len());
    let e = 5 + G.len();
    forged[e..e + 8].copy_from_slice(&now.to_be_bytes());
    forged[e + 8] = 3;
    for member in [&mut bo, &mut ada] {
        assert!(member.process_commit(G, &forged).is_err());
        assert!(
            !member.commit_strands(G, &forged).unwrap(),
            "bytes that never opened stranded a member"
        );
    }
    // One epoch above: still nothing; the head is what tells a device that
    // fell behind.
    forged[e..e + 8].copy_from_slice(&(now + 1).to_be_bytes());
    assert!(bo.process_commit(G, &forged).is_err());
    assert!(!bo.commit_strands(G, &forged).unwrap());
    // Both still read the group.
    let ok = ada.encrypt(G, b"still here").unwrap();
    assert!(matches!(
        bo.process_message(G, &ok).unwrap(),
        Incoming::Application { .. }
    ));
}

#[test]
fn a_real_commit_nobody_refused_strands_nobody() {
    let (mut ada, mut bo, _cy) = trio();
    let c = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    // Asked about a commit the commit door has not refused: no.
    assert!(!bo.commit_strands(G, &c.commit).unwrap());
    bo.process_commit(G, &c.commit).unwrap();
    assert!(!bo.commit_strands(G, &c.commit).unwrap());
}

/// The one thing that still strands: a commit that opened and verified at
/// this device's epoch, built by a member, that this device refused.
#[cfg(feature = "test-forgery")]
#[test]
fn a_verified_commit_this_device_refused_at_its_own_epoch_strands_it() {
    let (mut ada, mut bo, _cy) = trio();
    // Ada names herself the only admin.
    let meta = format!(r#"{{"v":1,"n":"Walk","adm":["{ADA}"]}}"#);
    let adm = ada.set_group_meta(G, meta.as_bytes()).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &adm.commit).unwrap();
    // Bo, not an admin, forges a removal of Ada; Ada refuses it by policy.
    let ada_leaf = bo.leaf_of_device(G, ADA_D).unwrap();
    let forged = bo.forge_remove_leaf(G, ada_leaf).unwrap();
    let refused = ada.process_commit(G, &forged.commit);
    assert!(
        matches!(refused, Err(Error::PolicyRefused(_))),
        "{refused:?}"
    );
    assert!(ada.commit_strands(G, &forged.commit).unwrap());
    // About other bytes, the record says nothing.
    let other = ada.encrypt(G, b"hi").unwrap();
    assert!(!ada.commit_strands(G, &other).unwrap());
}

#[test]
fn a_squatted_seat_gives_way_to_the_welcome_the_head_names() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut carol = client(&server, 5, "actor-carol", "device-carol-phone");
    ada.create_group(G).unwrap();
    let mut laptop = client(&server, 3, "actor-ada", "device-ada-laptop");

    // Carol, who knows G, founds her own group under it and seats Ada's new
    // laptop there first.
    carol.create_group(G).unwrap();
    let kp = laptop.generate_key_package().unwrap();
    let fake = carol.add_member(G, &kp).unwrap();
    carol.merge_pending_commit(G).unwrap();
    laptop
        .join_from_welcome(&fake.welcome.unwrap())
        .expect("nothing yet tells the laptop this is not G");

    // The real seat arrives and is refused, as before, but kept.
    ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let kp2 = laptop.generate_key_package().unwrap();
    let real = ada.add_member(G, &kp2).unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert!(matches!(
        laptop.join_from_welcome(&real.welcome.unwrap()),
        Err(Error::AlreadyAMember)
    ));
    assert_eq!(laptop.contested_welcome_group_id().as_deref(), Some(G));

    // The head is Ada's group: the laptop's copy is not it, the Welcome is.
    let (epoch, verifier) = head_of(&ada);
    assert_eq!(
        laptop.join_contested_welcome(epoch, &verifier).unwrap(),
        G.to_vec()
    );
    assert_eq!(laptop.contested_welcome_group_id(), None);
    assert_eq!(laptop.epoch(G).unwrap(), epoch);
    let hello = ada.encrypt(G, b"hello laptop").unwrap();
    match laptop.process_message(G, &hello).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"hello laptop"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

#[test]
fn a_held_group_that_is_the_head_keeps_its_seat() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut carol = client(&server, 5, "actor-carol", "device-carol-phone");
    let mut laptop = client(&server, 3, "actor-ada", "device-ada-laptop");
    ada.create_group(G).unwrap();
    let kp = laptop.generate_key_package().unwrap();
    let real = ada.add_member(G, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    laptop.join_from_welcome(&real.welcome.unwrap()).unwrap();

    // Carol's impostor Welcome comes second, from past the laptop's epoch.
    carol.create_group(G).unwrap();
    past_the_mark(&mut carol, G);
    let kp2 = laptop.generate_key_package().unwrap();
    let fake = carol.add_member(G, &kp2).unwrap();
    carol.merge_pending_commit(G).unwrap();
    assert!(matches!(
        laptop.join_from_welcome(&fake.welcome.unwrap()),
        Err(Error::AlreadyAMember)
    ));
    let (epoch, verifier) = head_of(&ada);
    assert!(matches!(
        laptop.join_contested_welcome(epoch, &verifier),
        Err(Error::AlreadyAMember)
    ));
    // Still Ada's group.
    let hello = ada.encrypt(G, b"still ada's").unwrap();
    assert!(matches!(
        laptop.process_message(G, &hello).unwrap(),
        Incoming::Application { .. }
    ));
    // Nothing is left waiting.
    assert!(laptop.join_contested_welcome(epoch, &verifier).is_err());
}

#[test]
fn a_welcome_the_head_does_not_name_does_not_replace_anything() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut carol = client(&server, 5, "actor-carol", "device-carol-phone");
    let mut laptop = client(&server, 3, "actor-ada", "device-ada-laptop");
    ada.create_group(G).unwrap();
    carol.create_group(G).unwrap();
    let kp = laptop.generate_key_package().unwrap();
    let fake = carol.add_member(G, &kp).unwrap();
    carol.merge_pending_commit(G).unwrap();
    laptop.join_from_welcome(&fake.welcome.unwrap()).unwrap();

    // A real Welcome, but the group has moved on since: the head names
    // neither copy, and the laptop keeps what it holds for the fork check.
    ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let kp2 = laptop.generate_key_package().unwrap();
    let real = ada.add_member(G, &kp2).unwrap();
    ada.merge_pending_commit(G).unwrap();
    ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert!(matches!(
        laptop.join_from_welcome(&real.welcome.unwrap()),
        Err(Error::AlreadyAMember)
    ));
    let (epoch, verifier) = head_of(&ada);
    assert!(matches!(
        laptop.join_contested_welcome(epoch, &verifier),
        Err(Error::AlreadyAMember)
    ));
}

/// A squatter's epoch is no wall. A device that took a squatter's Welcome
/// without a head holds an unconfirmed copy, which
/// raises no mark: the real group's Welcome at or below the squatter's epoch
/// is taken against the head and replaces it. Taken against the head in the
/// first place, the squat above the head is refused outright.
#[test]
fn a_real_welcome_at_or_below_the_squatters_epoch_is_taken_at_the_head() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut carol = client(&server, 5, "actor-carol", "device-carol-phone");
    let mut laptop = client(&server, 3, "actor-ada", "device-ada-laptop");
    ada.create_group(G).unwrap();
    carol.create_group(G).unwrap();
    carol.self_update(G).unwrap();
    carol.merge_pending_commit(G).unwrap();
    let fake = carol
        .add_member(G, &laptop.generate_key_package().unwrap())
        .unwrap();
    carol.merge_pending_commit(G).unwrap();
    let fake = fake.welcome.unwrap();
    laptop.join_from_welcome(&fake).unwrap();
    let squatted = laptop.epoch(G).unwrap();

    // Ada's Welcome seals an epoch at or below the squatter's: taken.
    let early = ada
        .add_member(G, &laptop.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    let (epoch, verifier) = head_of(&ada);
    assert!(epoch <= squatted);
    assert_eq!(
        laptop
            .join_from_welcome_at_head(&early.welcome.unwrap(), epoch, &verifier)
            .unwrap(),
        G
    );
    assert_eq!(head_of(&laptop), head_of(&ada));
    let hello = ada.encrypt(G, b"hello laptop").unwrap();
    assert!(matches!(
        laptop.process_message(G, &hello).unwrap(),
        Incoming::Application { .. }
    ));

    // Against the head, the same kind of squat never seats a new device.
    let mut tablet = client(&server, 4, "actor-ada", "device-ada-tablet");
    let fake = carol
        .add_member(G, &tablet.generate_key_package().unwrap())
        .unwrap();
    carol.merge_pending_commit(G).unwrap();
    assert!(matches!(
        tablet.join_from_welcome_at_head(&fake.welcome.unwrap(), epoch, &verifier),
        Err(Error::AlreadyAMember)
    ));
    assert!(matches!(tablet.epoch(G), Err(Error::NoSuchGroup)));
}

#[test]
fn a_seat_ask_is_taken_in_once() {
    let (mut ada, bo, _cy) = trio();
    let proof = bo.sign_join_request(G).unwrap();
    assert!(!ada.join_request_seen(G, &proof).unwrap());
    assert!(
        !ada.join_request_seen(G, &proof).unwrap(),
        "asking without taking it in kept a record"
    );
    assert!(ada.first_sight_of_join_request(G, &proof).unwrap());
    assert!(ada.join_request_seen(G, &proof).unwrap());
    assert!(
        !ada.first_sight_of_join_request(G, &proof).unwrap(),
        "the same ask, delivered again, was taken in again"
    );
    // The verdict itself is unchanged, as often as a caller asks it.
    let kp = bo.generate_key_package().unwrap();
    for _ in 0..2 {
        assert_eq!(
            ada.verify_join_request(G, BO, BO_D, &proof, &kp, &[]),
            JoinRequestVerdict::Accepted
        );
    }
    // A fresh ask from the same device is a fresh nonce.
    let again = bo.sign_join_request(G).unwrap();
    assert!(ada.first_sight_of_join_request(G, &again).unwrap());
    // The same proof under another group is another ask (and fails to verify
    // there anyway).
    assert!(ada
        .first_sight_of_join_request(b"another-group", &proof)
        .unwrap());
    // Bytes that are not a proof seat nobody.
    assert!(!ada.first_sight_of_join_request(G, b"junk").unwrap());
    assert!(!ada.join_request_seen(G, b"junk").unwrap());
}

/// A member who learns a pending ask's nonce (from the server, or by reading
/// the same envelope) signs an ask of its own under that nonce and has it
/// delivered first. It is another ask: the genuine one is still taken in
/// once, and only its own repeat is dropped.
#[test]
fn an_ask_signed_by_another_under_the_same_nonce_does_not_preempt_the_genuine_one() {
    let (mut ada, bo, _cy) = trio();
    let genuine = bo.sign_join_request(G).unwrap();
    let issued_at = i64::from_be_bytes(genuine[1..9].try_into().unwrap());
    let nonce = &genuine[9..25];
    let squat =
        peachy_mls_core::sign_join_request(&support::device_seed(3), G, CY, CY_D, issued_at, nonce)
            .unwrap();
    assert_eq!(&squat[..25], &genuine[..25], "the same time and nonce");
    assert!(ada.first_sight_of_join_request(G, &squat).unwrap());
    // Bytes that carry the nonce under a signature nobody made are another
    // ask too.
    let mut garbled = genuine.clone();
    garbled[40] ^= 1;
    assert!(ada.first_sight_of_join_request(G, &garbled).unwrap());

    assert!(!ada.join_request_seen(G, &genuine).unwrap());
    assert!(
        ada.first_sight_of_join_request(G, &genuine).unwrap(),
        "an ask another device signed under the nonce made the genuine one a repeat"
    );
    assert!(!ada.first_sight_of_join_request(G, &genuine).unwrap());
}

#[test]
fn a_seat_ask_is_remembered_across_a_restart() {
    use peachy_mls_core::{MemoryKv, PeachyStorage};
    let server = issuer();
    let kv = MemoryKv::new();
    let bo = client(&server, 2, BO, BO_D);
    let proof = bo.sign_join_request(G).unwrap();
    {
        let mut ada = support::client_on(
            &server,
            1,
            ADA,
            ADA_D,
            PeachyStorage::open(Box::new(kv.clone())).unwrap(),
        );
        assert!(ada.first_sight_of_join_request(G, &proof).unwrap());
    }
    let mut ada = support::client_on(
        &server,
        1,
        ADA,
        ADA_D,
        PeachyStorage::open(Box::new(kv)).unwrap(),
    );
    assert!(!ada.first_sight_of_join_request(G, &proof).unwrap());
}
