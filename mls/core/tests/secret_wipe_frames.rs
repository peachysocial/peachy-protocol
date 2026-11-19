// SPDX-License-Identifier: MIT
//! The secrets the core seals and opens for others are wiped from every heap
//! block it frees: a Welcome's gap block (the envelope secrets of the epochs
//! a joiner missed), a call's media grant (the sender's media secret), a
//! call's keys (the call root and every sender key, raw and in the JSON
//! door's hex), and the statement that keys an encrypted store (the store
//! key, in hex).
//!
//! An allocator stands in front of the system's for this test binary and
//! looks at every block as it is freed; one holding a secret under test is
//! counted. The inputs and outputs the test itself holds are made before it
//! arms and dropped after, so what is counted is the core's own copies. One
//! test in this file, so no other test's frees run beside it. SQLite's own
//! allocations go through its C allocator, not this one, so the store key
//! SQLCipher keeps is not looked at here.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

mod support;

use peachy_mls_core::call::{
    call_media_pq_key_pair, call_sender_key, open_call_media_grant, seal_call_media_grant,
    MediaGrantPayload, CALL_EXPORTER_LABEL, CALL_EXPORTER_LABEL_V2,
};
use peachy_mls_core::welcome_frame::{open_gap_block, seal_gap_block};
use peachy_mls_core::{Client, SqliteKv};
use sha2::Digest as _;
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-wipe-call-group";
const CALL_ID: [u8; 16] = *b"0123456789abcdef";
const CALL_ID_HEX: &str = "30313233343536373839616263646566";

/// Two members of one group, made before anything arms.
fn two_members() -> (Client, Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let added = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge the add");
    bo.join_from_welcome(&added.welcome.clone().expect("welcome"))
        .expect("bo joins");
    (ada, bo)
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex"))
        .collect()
}

struct Watching;

static ARMED: AtomicBool = AtomicBool::new(false);
static UNWIPED: AtomicUsize = AtomicUsize::new(0);
static NEEDLES: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            // `try_lock`: the needles are never freed while armed, and a
            // dealloc must not wait on a lock.
            if let Ok(needles) = NEEDLES.try_lock() {
                let block = std::slice::from_raw_parts(ptr, layout.size());
                for needle in needles.iter() {
                    if block.windows(needle.len()).any(|w| w == &needle[..]) {
                        UNWIPED.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

/// 32 bytes with no run of zeros in them, so a wiped block cannot match.
fn secret(label: &str) -> [u8; 32] {
    sha2::Sha256::digest(label.as_bytes()).into()
}

/// How many freed blocks held a needle while `run` ran.
fn unwiped_during(needles: Vec<Vec<u8>>, run: impl FnOnce()) -> usize {
    *NEEDLES.lock().expect("needles") = needles;
    UNWIPED.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    run();
    ARMED.store(false, Ordering::SeqCst);
    UNWIPED.load(Ordering::SeqCst)
}

#[test]
fn the_core_wipes_gap_secrets_media_secrets_and_the_store_key_from_what_it_frees() {
    // A gap block: sealed, then opened, and what it opened dropped while
    // armed, since that copy is the core's type and wipes itself.
    let key = secret("peachy wipe gap key");
    let gap: Vec<(u64, [u8; 32])> = (0..3)
        .map(|n| (40 + n, secret(&format!("peachy wipe gap secret {n}"))))
        .collect();
    let needles = gap.iter().map(|(_, s)| s.to_vec()).collect();
    let mut block = Vec::new();
    let unwiped = unwiped_during(needles, || {
        block = seal_gap_block(&key, &gap).expect("seal the gap block");
        let opened = open_gap_block(&key, &block).expect("open the gap block");
        assert_eq!(&opened[..], &gap[..]);
    });
    assert_eq!(
        unwiped, 0,
        "a block the core freed sealing or opening a gap block still held a gap secret"
    );

    // A media grant: sealed to a call key, then opened with it.
    let (private, public) = call_media_pq_key_pair(&secret("peachy wipe call key")).expect("pair");
    let media = secret("peachy wipe media secret");
    let payload = MediaGrantPayload {
        generation: 7,
        secret: media.into(),
        session_id: "session".into(),
        track_names: vec!["audio".into(), "video".into()],
    };
    let call_id = *b"0123456789abcdef";
    let unwiped = unwiped_during(vec![media.to_vec()], || {
        let (enc, ciphertext) =
            seal_call_media_grant(&public, &call_id, 1, 2, &payload).expect("seal the grant");
        let opened = open_call_media_grant(&private, &call_id, 1, 2, &enc, &ciphertext)
            .expect("open the grant");
        assert_eq!(opened, payload);
    });
    assert_eq!(
        unwiped, 0,
        "a block the core freed sealing or opening a media grant still held the media secret"
    );

    // A grant the encoder refuses (a track name past the limit) is refused
    // before its secret is written anywhere.
    let refused = MediaGrantPayload {
        track_names: vec!["audio".into(), "t".repeat(257)],
        ..payload.clone()
    };
    let unwiped = unwiped_during(vec![media.to_vec()], || {
        assert!(seal_call_media_grant(&public, &call_id, 1, 2, &refused).is_err());
    });
    assert_eq!(
        unwiped, 0,
        "a block the core freed refusing a media grant still held the media secret"
    );

    // A call's keys, the ring a door asks for at each epoch: dropped while
    // armed, since that copy is the core's type and wipes itself. The packed
    // form is the caller's (the C door hands it out, and its free wipes it).
    let (mut ada, _bo) = two_members();
    let root = ada
        .export_secret(GROUP, CALL_EXPORTER_LABEL, &CALL_ID, 32)
        .expect("export the call root");
    let mut needles = vec![root.clone()];
    for leaf in 0..2 {
        needles.push(call_sender_key(&root, leaf).expect("a sender key").to_vec());
    }
    let unwiped = unwiped_during(needles, || {
        let keys = ada.call_keys(GROUP, &CALL_ID).expect("the call's keys");
        assert_eq!(keys.senders.len(), 2);
        let mut packed = keys.to_bytes();
        drop(keys);
        zeroize::Zeroize::zeroize(&mut packed);
    });
    assert_eq!(
        unwiped, 0,
        "a block the core freed handing out a call's keys still held its root or a sender key"
    );

    // A v2 call's keys, raw and through the JSON door, which spells each
    // sender key in hex. The answer is the caller's, held until the end.
    let start = ada
        .call_media_json(
            GROUP,
            &format!(
                r#"{{"op":"start","callId":"{CALL_ID_HEX}","participantId":"p-ada","sessionId":"s-ada","trackNames":["a"]}}"#
            ),
        )
        .expect("start the call");
    let request = format!(r#"{{"op":"keys","callId":"{CALL_ID_HEX}"}}"#);
    let listed = ada
        .call_media_json(GROUP, &request)
        .expect("the call's keys");
    let listed: serde_json::Value = serde_json::from_str(&listed).expect("JSON");
    let key_hex = listed["senders"][0]["senderKeyHex"]
        .as_str()
        .expect("this device's own key")
        .to_owned();
    let root_v2 = ada
        .export_secret(GROUP, CALL_EXPORTER_LABEL_V2, &CALL_ID, 32)
        .expect("export the v2 call root");
    let needles = vec![root_v2, unhex(&key_hex), key_hex.clone().into_bytes()];
    let mut answer = String::new();
    let unwiped = unwiped_during(needles, || {
        let keys = ada
            .call_media_keys(GROUP, &CALL_ID, false)
            .expect("the call's keys");
        assert_eq!(keys.senders.len(), 1);
        drop(keys);
        answer = ada
            .call_media_json(GROUP, &request)
            .expect("the keys through the JSON door");
    });
    assert!(answer.contains(&key_hex), "{answer}");
    assert_eq!(
        unwiped, 0,
        "a block the core freed handing out a v2 call's keys still held its root or a sender key"
    );
    drop((start, answer));

    // An encrypted store, opened under a key: the core spells the key out
    // in hex for SQLCipher, and that statement is wiped.
    let store_key = secret("peachy wipe store key");
    let hex: String = store_key.iter().map(|b| format!("{b:02X}")).collect();
    let path =
        std::env::temp_dir().join(format!("peachy-secret-wipe-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let unwiped = unwiped_during(vec![hex.into_bytes()], || {
        drop(SqliteKv::open_encrypted(&path, &store_key).expect("open the store"));
    });
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    assert_eq!(
        unwiped, 0,
        "a block the core freed keying the store still held the store key in hex"
    );
}
