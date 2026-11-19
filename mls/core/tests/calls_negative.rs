// SPDX-License-Identifier: MIT
//! THE CALL NEGATIVES, AT THE FRAME: N16 of
//! docs/calls.md §Negative tests;
//! and, on the real `Client`, N3 (forward secrecy), N4 (label separation),
//! N6 (lane authentication), N17 (the live lane's replay window) and R-K9
//! (no grace for the live key).
//! They run with the rest of the workspace's tests
//! (`cargo test --workspace --all-features` in `mls/`).
//!
//! `calls_fixture.rs` proves the KEYS move on every epoch and a removed
//! member's ring differs. This file carries real media frames through those
//! keys, in the wire format every client's frame encryptor writes (the
//! WebRTC frame-encryption trailer; the web client's frame encryption
//! writes it byte for byte):
//!
//! ```text
//! wire = header (n clear) ‖ AES-128-GCM(frame_key, iv, aad = header, rest) ‖ iv (12) ‖ 0x0C ‖ key_index
//! ```
//!
//! and asks the two questions a key comparison cannot answer:
//!
//! 1. **A removed member decrypts nothing after the rekey.** Not with its last
//!    ring, not with any leaf's key it can derive from the last call root it
//!    held, not after it processes the commit that removed it.
//! 2. **A recording at the SFU is undecodable without the frame key.** What
//!    the SFU forwards, and what our server holds or is told (the group
//!    handle, the call id, the send key every call rpc proves membership
//!    with, its verifier), opens no frame — and the only plaintext on the wire
//!    is the clear header the SFU must read to route.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use peachy_mls_core::call::{
    append_live_signature, call_frame_key, call_key_index, call_sender_key, encode_call_signal,
    live_signature_statement, seal_live_frame, CallKeys, CallLane, CallMedia, CallSignal,
    CallSignalBody, HangupReason, LiveStamp, CALL_EXPORTER_LABEL, CALL_LIVE_EXPORTER_LABEL,
    CALL_LIVE_MAX_SKEW_MS,
};
use peachy_mls_core::envelope::group_handle;
use peachy_mls_core::{Client, Incoming, MemoryKv, PeachyStorage};
use sha2::{Digest, Sha256};
use support::{client, client_on, issuer, NOW};

/// The test clock in milliseconds, which is what a live frame's stamp is.
const NOW_MS: u64 = NOW as u64 * 1000;

const GROUP: &[u8] = b"peachy-call-negative-group";
const CALL_ID: [u8; 16] = *b"fedcba9876543210";
/// The label the conversation's send key is exported under (the delivery service:
/// what the call rpcs carry to the server).
const SEALED_SENDER_LABEL: &str = "peachy sealed-sender v1";
/// The typing indicator's exporter label (the web client's typing code).
const TYPING_LABEL: &str = "peachy typing v1";

const IV_BYTES: usize = 12;

/// One frame as a client's frame encryptor sends it.
fn encrypt_frame(
    frame_key: &[u8; 16],
    clear: usize,
    data: &[u8],
    iv: [u8; 12],
    key_index: u8,
) -> Vec<u8> {
    let n = clear.min(data.len());
    let (header, rest) = data.split_at(n);
    let ct = Aes128Gcm::new_from_slice(frame_key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: rest,
                aad: header,
            },
        )
        .unwrap();
    let mut out = Vec::with_capacity(n + ct.len() + IV_BYTES + 2);
    out.extend_from_slice(header);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&iv);
    out.push(IV_BYTES as u8);
    out.push(key_index);
    out
}

/// One frame opened with one candidate key, as a receiver's frame encryptor
/// would: `None` is a dropped frame.
fn decrypt_frame(frame_key: &[u8], clear: usize, wire: &[u8]) -> Option<Vec<u8>> {
    if wire.len() < clear + 16 + IV_BYTES + 2 || wire[wire.len() - 2] as usize != IV_BYTES {
        return None;
    }
    let body = &wire[..wire.len() - 2];
    let (front, iv) = body.split_at(body.len() - IV_BYTES);
    let (header, ct) = front.split_at(clear);
    let cipher = Aes128Gcm::new_from_slice(frame_key).ok()?;
    let rest = cipher
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: ct,
                aad: header,
            },
        )
        .ok()?;
    let mut out = header.to_vec();
    out.extend_from_slice(&rest);
    Some(out)
}

/// An Opus frame (TOC byte clear), a VP8 key frame (10 clear) and a VP8 delta
/// (3 clear), each with a payload no header byte repeats.
fn frames() -> Vec<(&'static str, usize, Vec<u8>)> {
    let payload = |tag: u8, len: usize| {
        (0..len)
            .map(|i| tag ^ (i as u8).wrapping_mul(37))
            .collect::<Vec<u8>>()
    };
    let mut opus = vec![0x78];
    opus.extend(payload(0xa5, 80));
    let mut key = vec![0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x80, 0x02, 0xe0, 0x01];
    key.extend(payload(0x3c, 400));
    let mut delta = vec![0xb1, 0x01, 0x00];
    delta.extend(payload(0x5e, 160));
    vec![
        ("audio", 1, opus),
        ("vp8 key frame", 10, key),
        ("vp8 delta", 3, delta),
    ]
}

fn frame_key_of(keys: &CallKeys, leaf: u32) -> [u8; 16] {
    let sender = keys
        .senders
        .iter()
        .find(|s| s.leaf_index == leaf)
        .expect("the sender is in the ring");
    call_frame_key(&*sender.key).unwrap()
}

/// Every frame key a holder of `root` can derive: each leaf of a tree this
/// size and then some.
fn every_key_from_root(root: &[u8]) -> Vec<[u8; 16]> {
    (0..16u32)
        .map(|leaf| call_frame_key(&call_sender_key(root, leaf).unwrap()).unwrap())
        .collect()
}

fn three_members() -> (Client, Client, Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let mut cy = client(&server, 3, "actor-cy", "device-cy-phone");
    ada.create_group(GROUP).unwrap();
    let bo_kp = bo.generate_key_package().unwrap();
    let added = ada.add_member(GROUP, &bo_kp).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.join_from_welcome(&added.welcome.clone().unwrap())
        .unwrap();
    let cy_kp = cy.generate_key_package().unwrap();
    let added = ada.add_member(GROUP, &cy_kp).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &added.commit).unwrap();
    cy.join_from_welcome(&added.welcome.clone().unwrap())
        .unwrap();
    (ada, bo, cy)
}

#[test]
fn a_removed_member_decrypts_no_frame_after_the_rekey() {
    let (mut ada, mut bo, mut cy) = three_members();
    let ada_leaf = ada.leaf_of_device(GROUP, "device-ada-phone").unwrap();
    let bo_leaf = bo.leaf_of_device(GROUP, "device-bo-phone").unwrap();

    // Before the removal Cy is in the call and reads Ada's frames: the
    // instrument works, so the refusals below are the removal's doing.
    let shared = ada.call_keys(GROUP, &CALL_ID).unwrap();
    let cy_last = cy.call_keys(GROUP, &CALL_ID).unwrap();
    assert_eq!(cy_last, shared);
    let (_, clear, frame) = &frames()[0];
    let before = encrypt_frame(
        &frame_key_of(&shared, ada_leaf),
        *clear,
        frame,
        [1; 12],
        shared.key_index,
    );
    assert_eq!(
        decrypt_frame(&frame_key_of(&cy_last, ada_leaf), *clear, &before).as_ref(),
        Some(frame)
    );

    // Ada removes Cy. Bo merges it; the call rekeys on the new epoch.
    let cy_leaf = ada.leaf_of_device(GROUP, "device-cy-phone").unwrap();
    let removal = ada.remove_leaf(GROUP, cy_leaf).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    assert!(matches!(
        bo.process_commit(GROUP, &removal.commit).unwrap(),
        Incoming::Commit(_)
    ));
    let after = ada.call_keys(GROUP, &CALL_ID).unwrap();
    assert_eq!(after.epoch, shared.epoch + 1);
    assert_eq!(after.key_index, call_key_index(after.epoch));
    assert_eq!(bo.call_keys(GROUP, &CALL_ID).unwrap(), after);

    // Everything Cy can still bring to bear: its last ring, every leaf's key
    // derivable from the last call root it held, and the group's send key and
    // exporter outputs at its own (stale) epoch.
    let mut cy_keys: Vec<[u8; 16]> = cy_last
        .senders
        .iter()
        .map(|s| call_frame_key(&*s.key).unwrap())
        .collect();
    cy_keys.extend(every_key_from_root(&*cy_last.call_root));
    let cy_send_key = cy
        .export_secret(GROUP, SEALED_SENDER_LABEL, GROUP, 32)
        .unwrap();
    cy_keys.extend(every_key_from_root(&cy_send_key));
    cy_keys.push(cy_send_key[..16].try_into().unwrap());

    let mut iv = 100u8;
    for (sender, leaf) in [("ada", ada_leaf), ("bo", bo_leaf)] {
        let key = frame_key_of(&after, leaf);
        for (kind, clear, frame) in frames() {
            iv += 1;
            let wire = encrypt_frame(&key, clear, &frame, [iv; 12], after.key_index);
            // The remaining members read it.
            let bo_key = frame_key_of(&bo.call_keys(GROUP, &CALL_ID).unwrap(), leaf);
            assert_eq!(
                decrypt_frame(&bo_key, clear, &wire),
                Some(frame.clone()),
                "{sender}'s {kind} opens for Bo"
            );
            // Cy reads nothing.
            for (i, k) in cy_keys.iter().enumerate() {
                assert_eq!(
                    decrypt_frame(k, clear, &wire),
                    None,
                    "{sender}'s {kind} after the removal opened under Cy's candidate key {i}"
                );
            }
            // And the trailer names a slot Cy's ring does not fill.
            assert_ne!(*wire.last().unwrap(), cy_last.key_index);
        }
    }

    // Cy processing the commit that removed it gives it no new epoch to
    // derive from: either it is refused, or the group is gone, and in no case
    // does Cy end with the new call root.
    let _ = cy.process_commit(GROUP, &removal.commit);
    if let Ok(k) = cy.call_keys(GROUP, &CALL_ID) {
        assert_ne!(
            k.call_root, after.call_root,
            "a removed member derived the new epoch's call root"
        );
        let key = frame_key_of(&after, ada_leaf);
        let (_, clear, frame) = &frames()[1];
        let wire = encrypt_frame(&key, *clear, frame, [9; 12], after.key_index);
        for leaf_key in every_key_from_root(&*k.call_root) {
            assert_eq!(decrypt_frame(&leaf_key, *clear, &wire), None);
        }
    }
}

#[test]
fn a_recording_at_the_sfu_is_undecodable_without_the_frame_key() {
    let (ada, bo, _cy) = three_members();
    let keys = ada.call_keys(GROUP, &CALL_ID).unwrap();
    let ada_leaf = ada.leaf_of_device(GROUP, "device-ada-phone").unwrap();
    let bo_leaf = bo.leaf_of_device(GROUP, "device-bo-phone").unwrap();
    let frame_key = frame_key_of(&keys, ada_leaf);

    // What the operator holds or is told: the conversation's handle, the call
    // id, the send key every call rpc carries (and its verifier, which the
    // head stores), the epoch and slot. And the obvious mistakes a client
    // could make with them, so a regression to any of them is caught.
    let send_key = ada
        .export_secret(GROUP, SEALED_SENDER_LABEL, GROUP, 32)
        .unwrap();
    let handle = group_handle(GROUP).unwrap();
    let verifier: [u8; 32] = Sha256::digest(&send_key).into();
    let mut operator: Vec<(String, Vec<u8>)> = vec![
        ("zeros".into(), vec![0; 16]),
        ("send key".into(), send_key[..16].to_vec()),
        ("send key tail".into(), send_key[16..].to_vec()),
        ("handle".into(), handle[..16].to_vec()),
        ("verifier".into(), verifier[..16].to_vec()),
        ("call id".into(), CALL_ID.to_vec()),
    ];
    for (name, root) in [
        ("send key", send_key.clone()),
        ("handle", handle.to_vec()),
        ("verifier", verifier.to_vec()),
    ] {
        for (leaf, k) in every_key_from_root(&root).into_iter().enumerate() {
            operator.push((format!("{name} as a call root, leaf {leaf}"), k.to_vec()));
        }
        operator.push((
            format!("{name} as a sender key"),
            call_frame_key(&root[..16]).unwrap().to_vec(),
        ));
    }
    // A call root exported under the wrong call id is another call's key.
    let other_call = ada.call_keys(GROUP, b"0000000000000000").unwrap();
    operator.push((
        "another call's key, same leaf".into(),
        frame_key_of(&other_call, ada_leaf).to_vec(),
    ));
    // A member's own key is not another member's: Bo cannot pass his frames
    // off as Ada's, nor read hers with his.
    operator.push((
        "bo's own frame key".into(),
        frame_key_of(&keys, bo_leaf).to_vec(),
    ));
    // The sender key itself, not run through the frame encryptor's HKDF.
    operator.push((
        "ada's sender key, raw".into(),
        keys.senders
            .iter()
            .find(|s| s.leaf_index == ada_leaf)
            .unwrap()
            .key
            .to_vec(),
    ));

    let mut send_count = 0u32;
    for (kind, clear, frame) in frames() {
        send_count += 1;
        let mut iv = [0u8; 12];
        iv[..4].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        iv[4..8].copy_from_slice(&(90_000 * send_count).to_be_bytes());
        iv[8..].copy_from_slice(&(90_000 * send_count - 7).to_be_bytes());
        let wire = encrypt_frame(&frame_key, clear, &frame, iv, keys.key_index);

        // The instrument: the frame key opens it.
        assert_eq!(
            decrypt_frame(&frame_key, clear, &wire),
            Some(frame.clone()),
            "{kind} round-trips"
        );

        // The recording's plaintext is the clear header and nothing more.
        assert_eq!(
            &wire[..clear],
            &frame[..clear],
            "{kind}: the SFU reads the header"
        );
        let payload = &frame[clear..];
        for window in payload.windows(6) {
            assert!(
                !wire[clear..].windows(6).any(|w| w == window),
                "{kind}: six payload bytes appear in the clear on the wire"
            );
        }

        for (name, key) in &operator {
            assert_eq!(
                decrypt_frame(key, clear, &wire),
                None,
                "{kind} opened under the operator's {name}"
            );
        }

        // Nor does tampering get a decoder anywhere: a flipped ciphertext bit
        // or a rewritten header (the AAD) fails under the right key too.
        let mut flipped = wire.clone();
        flipped[clear + 2] ^= 0x01;
        assert_eq!(
            decrypt_frame(&frame_key, clear, &flipped),
            None,
            "{kind}: a flipped bit"
        );
        let mut reheadered = wire.clone();
        reheadered[0] ^= 0x01;
        assert_eq!(
            decrypt_frame(&frame_key, clear, &reheadered),
            None,
            "{kind}: a rewritten header"
        );
    }
}

/// N3, forward secrecy on the real core: once the group is at `e+1`, nothing
/// the device holds — not the live client, and not a client rebuilt from its
/// store, which is what a seized phone yields — derives `e`'s call root or
/// live key. No door takes an epoch: `call_keys` answers for the current one
/// only, and the staged-commit door answers for nothing once the commit is
/// merged.
#[test]
fn a_device_at_the_next_epoch_cannot_reproduce_the_last_ones_call_keys() {
    let server = issuer();
    let kv = MemoryKv::new();
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let bo_kp = bo.generate_key_package().unwrap();

    let (old, old_live) = {
        let mut ada = client_on(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            PeachyStorage::open(Box::new(kv.clone())).unwrap(),
        );
        ada.create_group(GROUP).unwrap();
        let added = ada.add_member(GROUP, &bo_kp).unwrap();
        ada.merge_pending_commit(GROUP).unwrap();
        bo.join_from_welcome(&added.welcome.clone().unwrap())
            .unwrap();

        let old = ada.call_keys(GROUP, &CALL_ID).unwrap();
        let old_live = ada
            .export_secret(GROUP, CALL_LIVE_EXPORTER_LABEL, &[], 32)
            .unwrap();
        let update = ada.self_update(GROUP).unwrap();
        // Before the merge the staged door answers e+1, never e.
        let pending = ada.pending_call_keys(GROUP, &CALL_ID).unwrap();
        assert_eq!(pending.epoch, old.epoch + 1);
        assert_ne!(pending.call_root, old.call_root);
        ada.merge_pending_commit(GROUP).unwrap();
        bo.process_commit(GROUP, &update.commit).unwrap();

        let now = ada.call_keys(GROUP, &CALL_ID).unwrap();
        assert_eq!(now.epoch, old.epoch + 1);
        assert_eq!(now.call_root, pending.call_root);
        assert_ne!(now.call_root, old.call_root);
        assert!(
            ada.pending_call_keys(GROUP, &CALL_ID).is_err(),
            "no staged commit, no staged keys"
        );
        (old, old_live)
    };

    // The seized device: a client rebuilt from what the store kept.
    let ada = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        PeachyStorage::open(Box::new(kv)).unwrap(),
    );
    assert_eq!(ada.epoch(GROUP).unwrap(), old.epoch + 1);
    let now = ada.call_keys(GROUP, &CALL_ID).unwrap();
    assert_eq!(now, bo.call_keys(GROUP, &CALL_ID).unwrap());
    assert_ne!(now.call_root, old.call_root);
    assert!(ada.pending_call_keys(GROUP, &CALL_ID).is_err());
    for sender in &old.senders {
        assert!(
            !now.senders.iter().any(|s| s.key == sender.key),
            "an epoch-{} sender key came back at epoch {}",
            old.epoch,
            now.epoch
        );
    }
    // Nor under any context or label it might be asked for.
    let contexts: [(&str, &[u8]); 5] = [
        (CALL_EXPORTER_LABEL, &CALL_ID),
        (CALL_EXPORTER_LABEL, &[]),
        (CALL_EXPORTER_LABEL, GROUP),
        (CALL_LIVE_EXPORTER_LABEL, &CALL_ID),
        (CALL_LIVE_EXPORTER_LABEL, &[]),
    ];
    for (label, context) in contexts {
        let out = ada.export_secret(GROUP, label, context, 32).unwrap();
        assert_ne!(out.as_slice(), old.call_root.as_slice(), "{label}");
        assert_ne!(out, old_live, "{label}");
    }
}

/// N4: one epoch, seven exporter outputs, all different. The server holds the
/// sealed-sender one (it is the send key every call rpc proves membership
/// with); label separation is all that keeps it from being a call key
/// (docs/calls.md §Security considerations, the exporter labels in use
/// per epoch).
#[test]
fn every_exporter_label_and_call_id_gives_its_own_secret() {
    let (ada, bo, _cy) = three_members();
    let other_call = *b"0000000000000000";
    let cases: [(&str, &str, &[u8]); 7] = [
        ("call", CALL_EXPORTER_LABEL, &CALL_ID),
        ("another call", CALL_EXPORTER_LABEL, &other_call),
        ("call, empty context", CALL_EXPORTER_LABEL, &[]),
        ("live", CALL_LIVE_EXPORTER_LABEL, &[]),
        ("live, call id context", CALL_LIVE_EXPORTER_LABEL, &CALL_ID),
        ("typing", TYPING_LABEL, GROUP),
        ("sealed-sender", SEALED_SENDER_LABEL, GROUP),
    ];
    let outputs: Vec<(&str, Vec<u8>)> = cases
        .iter()
        .map(|(name, label, context)| {
            let out = ada.export_secret(GROUP, label, context, 32).unwrap();
            // Every member derives the same one: separation is not divergence.
            assert_eq!(
                bo.export_secret(GROUP, label, context, 32).unwrap(),
                out,
                "{name}"
            );
            (*name, out)
        })
        .collect();
    for (i, (a, x)) in outputs.iter().enumerate() {
        assert_eq!(x.len(), 32, "{a}");
        for (b, y) in &outputs[i + 1..] {
            assert_ne!(x, y, "the {a} and {b} exporter outputs agree");
        }
    }
    // The call door uses the call label with the call id, and nothing else.
    let keys = ada.call_keys(GROUP, &CALL_ID).unwrap();
    assert_eq!(keys.call_root.as_slice(), outputs[0].1.as_slice());
    assert_eq!(
        ada.call_keys(GROUP, &other_call)
            .unwrap()
            .call_root
            .as_slice(),
        outputs[1].1.as_slice()
    );
    // No sender key is a slice of any exporter output.
    for sender in &keys.senders {
        for (name, out) in &outputs {
            assert_ne!(&out[..16], sender.key.as_slice(), "{name}");
            assert_ne!(&out[16..], sender.key.as_slice(), "{name}");
        }
    }
}

/// N6 on the real door: a live frame sealed under the epoch's own live key —
/// so it opens, which is the instrument — carrying an `Offer`, `Answer`,
/// `Hangup` or `Remove` is refused by `Client::open_call_signal`. Any member
/// can write one, and none names its sender, so none may ring, stop a ring or
/// remove anyone.
#[test]
fn a_ring_lane_signal_on_the_live_lane_is_refused() {
    let (ada, mut bo, _cy) = three_members();
    let live_key = ada
        .export_secret(GROUP, CALL_LIVE_EXPORTER_LABEL, &[], 32)
        .unwrap();
    let sent = std::cell::Cell::new(NOW_MS);
    let forge = |body: CallSignalBody| {
        sent.set(sent.get() + 1);
        seal_live_frame(
            &live_key,
            LiveStamp {
                sender_leaf: 0,
                sent_at_ms: sent.get(),
            },
            &encode_call_signal(&CallSignal::new(CALL_ID, body)).unwrap(),
        )
        .unwrap()
    };

    // The instrument: a live-lane body under the same key, signed by the leaf
    // it claims, opens.
    let heartbeat = {
        use ed25519_dalek::Signer as _;
        let stamp = LiveStamp {
            sender_leaf: 0,
            sent_at_ms: NOW_MS,
        };
        let mut signal = encode_call_signal(&CallSignal::new(
            CALL_ID,
            CallSignalBody::Joined {
                participant_id: "p-ada".into(),
                session_id: "ada-session".into(),
                track_names: Vec::new(),
                leaf_index: 0,
                media_key: Vec::new(),
                started_at_ms: 0,
                media_key_pq: Vec::new(),
                participation: None,
            },
        ))
        .unwrap();
        let (signing, _) = peachy_mls_core::issuer::device_key_pair(&support::device_seed(1));
        let statement = live_signature_statement(GROUP, ada.epoch(GROUP).unwrap(), stamp, &signal);
        append_live_signature(&mut signal, &signing.sign(&statement).to_bytes());
        seal_live_frame(&live_key, stamp, &signal).unwrap()
    };
    let opened = bo.open_call_signal(GROUP, &heartbeat).unwrap();
    assert_eq!(opened.lane, CallLane::Live);
    assert_eq!(opened.sender, None);

    for (name, body) in [
        (
            "offer",
            CallSignalBody::Offer {
                media: CallMedia::Video,
                ring: true,
                created_at_ms: 1_789_516_800_000,
            },
        ),
        ("answer", CallSignalBody::Answer),
        (
            "hangup",
            CallSignalBody::Hangup {
                reason: HangupReason::AcceptedElsewhere,
            },
        ),
        (
            "remove",
            CallSignalBody::Remove {
                target: "p-bo".into(),
            },
        ),
    ] {
        let err = bo.open_call_signal(GROUP, &forge(body)).unwrap_err();
        assert!(
            err.to_string().contains("must come on the MLS lane"),
            "{name}: {err}"
        );
    }
}

/// R-K9 (threat model D7): the live key has no grace window. A live frame a
/// removed member sealed under the epoch it was removed from opens for the
/// others until they merge the removal, and never after, so a removed member
/// cannot send `Left` for others, react or announce a session once the
/// removal is in.
#[test]
fn a_removed_members_live_frame_is_refused_once_the_removal_is_merged() {
    let (mut ada, mut bo, mut cy) = three_members();
    // Cy's heartbeat in a call it joined (its Left would go signed): a live
    // frame.
    let cy_own_leaf = cy.leaf_of_device(GROUP, "device-cy-phone").unwrap();
    cy.call_media_start(
        GROUP,
        &CALL_ID,
        "p-cy",
        "sess-cy",
        &["sess-cy-audio".into()],
    )
    .unwrap();
    let stale = cy
        .seal_call_signal(
            GROUP,
            &CallSignal::new(
                CALL_ID,
                CallSignalBody::Joined {
                    participant_id: "p-cy".into(),
                    session_id: "sess-cy".into(),
                    track_names: vec!["sess-cy-audio".into()],
                    leaf_index: cy_own_leaf,
                    media_key: Vec::new(),
                    started_at_ms: 0,
                    media_key_pq: Vec::new(),
                    participation: None,
                },
            ),
        )
        .unwrap();
    let inner = bo.open_envelope(&stale).unwrap().unwrap().inner;
    // The instrument: before the removal it is an ordinary live frame.
    assert_eq!(
        bo.open_call_signal(GROUP, &inner).unwrap().lane,
        CallLane::Live
    );

    let cy_leaf = ada.leaf_of_device(GROUP, "device-cy-phone").unwrap();
    let removal = ada.remove_leaf(GROUP, cy_leaf).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &removal.commit).unwrap();

    for (who, member) in [("ada", &mut ada), ("bo", &mut bo)] {
        let err = member.open_call_signal(GROUP, &inner).unwrap_err();
        assert!(
            err.to_string().contains("did not open"),
            "{who} opened a removed member's live frame: {err}"
        );
    }
}

/// N17 (threat model D3): the live lane's replay window, on the real door.
/// The server relays every live frame and keeps none, but nothing stops it
/// recording one: before the window, a recorded `Left` sent again dropped a
/// participant's tile until its next signed `Joined`. Now a frame a receiver
/// has opened never opens for it again, and a recording older than the clock
/// bound opens for nobody, not even a receiver that never saw it.
#[test]
fn a_replayed_live_frame_is_refused() {
    let (mut ada, mut bo, mut cy) = three_members();
    // Ada's heartbeat in a call she joined: every Left goes signed, so the
    // live frame recorded here is a Joined.
    fn beat(who: &mut Client, opener: &Client) -> Vec<u8> {
        let leaf = who.leaf_of_device(GROUP, "device-ada-phone").unwrap();
        let envelope = who
            .seal_call_signal(
                GROUP,
                &CallSignal::new(
                    CALL_ID,
                    CallSignalBody::Joined {
                        participant_id: "p-ada".into(),
                        session_id: "sess-ada".into(),
                        track_names: vec!["sess-ada-audio".into()],
                        leaf_index: leaf,
                        media_key: Vec::new(),
                        started_at_ms: 0,
                        media_key_pq: Vec::new(),
                        participation: None,
                    },
                ),
            )
            .unwrap();
        opener.open_envelope(&envelope).unwrap().unwrap().inner
    }
    ada.call_media_start(
        GROUP,
        &CALL_ID,
        "p-ada",
        "sess-ada",
        &["sess-ada-audio".into()],
    )
    .unwrap();
    let recorded = beat(&mut ada, &bo);

    // The instrument: the first copy is an ordinary live frame.
    let opened = bo.open_call_signal(GROUP, &recorded).unwrap();
    assert_eq!(opened.lane, CallLane::Live);
    assert!(matches!(opened.signal.body, CallSignalBody::Joined { .. }));

    // The server sends it again: refused, however many times.
    for attempt in 0..3 {
        let err = bo.open_call_signal(GROUP, &recorded).unwrap_err();
        assert!(
            err.to_string().contains("refused as a replay"),
            "attempt {attempt}: {err}"
        );
    }

    // Ada's next frame is a new one and opens; the window refuses only what
    // it has seen.
    let next = beat(&mut ada, &bo);
    assert_ne!(next, recorded);
    bo.open_call_signal(GROUP, &next).unwrap();

    // A receiver that never saw the recording takes it once (it may be late,
    // not replayed)...
    cy.open_call_signal(GROUP, &recorded).unwrap();
    assert!(cy.open_call_signal(GROUP, &recorded).is_err());

    // ...but a recording older than the clock bound opens for nobody, so a
    // receiver that just joined, or restarted and lost its window, is not
    // fooled either.
    let live_key = ada
        .export_secret(GROUP, CALL_LIVE_EXPORTER_LABEL, &[], 32)
        .unwrap();
    let old = seal_live_frame(
        &live_key,
        LiveStamp {
            sender_leaf: 0,
            sent_at_ms: NOW_MS - CALL_LIVE_MAX_SKEW_MS - 1,
        },
        &encode_call_signal(&CallSignal::new(
            CALL_ID,
            CallSignalBody::Joined {
                participant_id: "p-ada".into(),
                session_id: "ada-session".into(),
                track_names: Vec::new(),
                leaf_index: 0,
                media_key: Vec::new(),
                started_at_ms: 0,
                media_key_pq: Vec::new(),
                participation: None,
            },
        ))
        .unwrap(),
    )
    .unwrap();
    for (who, member) in [("bo", &mut bo), ("cy", &mut cy)] {
        // This copy is unsigned, so it is refused for that ahead of the
        // window's clock bound (calls_clock_offset.rs pins the bound on its
        // own).
        let err = member.open_call_signal(GROUP, &old).unwrap_err();
        assert!(
            err.to_string().contains("refused as a replay (stale)")
                || err.to_string().contains("carries no signature"),
            "{who}: {err}"
        );
    }
}
