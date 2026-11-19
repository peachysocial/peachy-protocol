// SPDX-License-Identifier: MIT
//! A client's whole life frees no heap block still holding a secret it was
//! done with, through Rust's allocator, on either store a client runs on:
//! SQLite (the apps' groups) and the in-memory store (a call link's group,
//! `PeachyStorage::in_memory`). SQLite's own blocks (its page cache, its
//! parsed statements) come from its allocator, not Rust's, and are not seen.
//! docs/mls-core.md §Security considerations
//! says what is and is not wiped; this is the test that holds the
//! "is" to the code a client actually runs, end to end, rather than to one
//! path at a time.
//!
//! An allocator stands in front of the system's for this test binary, hands
//! out every block zeroed, and looks at every block as it is freed; one still holding a needle (a marker
//! message's words, a past epoch's envelope secret, the secret a held
//! envelope's device seal carried) is counted. Each step is watched only
//! while the client under test runs it, for the needles that step must not
//! leave behind:
//!
//! - joining by a Welcome, then commits of its own and of another member's,
//!   with every epoch already past as a needle (the epoch a commit leaves is
//!   derived in that commit, so it becomes a needle from the next one on);
//! - a message encrypted, opened and kept under its mailbox id, then
//!   released, and a message in a later epoch opened and not kept, with their
//!   words as the needles. OpenMLS frees blocks still holding a message's
//!   words in each encrypt and each decrypt (its AEAD output, the framed
//!   content parsed from it, the content it verifies and hands back);
//!   their count is pinned exactly ([`OPENMLS_ENCRYPT_COPIES`],
//!   [`OPENMLS_DECRYPT_COPIES`]), so a copy of the core's own is one more,
//!   and an OpenMLS that leaves fewer moves the pin;
//! - envelopes held on their device seals while the copy is forked, a pass
//!   that waits, the reseat, the pass that grants them, each opened on its
//!   grant and released, with the seal's secret as the needle; then one
//!   envelope that opens at once, with its inner bytes a needle too;
//! - and the client dropped, with every needle at once.
//!
//! Before the lives, an envelope's inner bytes (a seat ask's, a link
//! preview's) sealed and opened in each version, and a live call frame
//! sealed and opened, the caller wiping the copy it is handed; and a message refused after it opened (its keep refused by the
//! store, or its sender removed), which leaves only OpenMLS's copies.
//!
//! One test in this file, so no other test's frees run beside it. Run on x86_64
//! and on ARM in CI, next to `ghash_wipe.rs`.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use peachy_mls_core::call::frame::{open_live_frame, seal_live_frame, LiveStamp};
use peachy_mls_core::envelope::{
    open_envelope_for, open_epoch_envelope, seal_epoch_envelope, seal_group_id_envelope,
    ENVELOPE_KIND_LINK_PREVIEW, ENVELOPE_KIND_MESSAGE, ENVELOPE_KIND_SEAT_ASK,
    EPOCH_ENVELOPE_EXPORTER_LABEL,
};
use peachy_mls_core::hint::CONTENT_HINT_RESENDABLE;
use peachy_mls_core::{
    Client, Error, Incoming, KvEntry, KvError, KvStore, MemoryKv, PeachyStorage, SqliteKv,
};
use support::{client, client_on, device_seed, issuer, RemoveLeaf, NOW};
use zeroize::Zeroize;

struct Watching;

static ARMED: AtomicBool = AtomicBool::new(false);
/// Per needle, in the order watched: the freed blocks that held it.
static UNWIPED: [AtomicUsize; MAX_NEEDLES] = [const { AtomicUsize::new(0) }; MAX_NEEDLES];
static NEEDLES: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
const MAX_NEEDLES: usize = 32;

unsafe impl GlobalAlloc for Watching {
    /// Zeroed: a block holds only what was written to it since, never what a
    /// step not watched (another member's) left in that memory before.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            // `try_lock`: the needles are never freed while armed, and a
            // dealloc must not wait on a lock.
            if let Ok(needles) = NEEDLES.try_lock() {
                let block = std::slice::from_raw_parts(ptr, layout.size());
                for (i, needle) in needles.iter().enumerate() {
                    if !needle.is_empty() && block.windows(needle.len()).any(|w| w == &needle[..]) {
                        UNWIPED[i].fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

/// OpenMLS 0.9's own unwiped copies of a message's words: the freed blocks
/// one encrypt leaves holding them (the framed content and its serialization
/// in `create_message_internal` and `encrypt_content`), and one decrypt
/// (the AEAD output of openmls_rust_crypto's `aead_decrypt`, the content
/// `PrivateMessageIn::decrypt` parses from it, the copies `verify_no_out`
/// and `process_internal_authenticated_content` make). Listed in
/// docs/mls-core.md §Security considerations.
const OPENMLS_ENCRYPT_COPIES: usize = 6;
const OPENMLS_DECRYPT_COPIES: usize = 5;

/// One step's finding for one needle: how many freed blocks held it, and how
/// many OpenMLS itself is pinned to leave.
struct Finding {
    label: String,
    needle: usize,
    found: usize,
    pinned: usize,
}

/// What one life found, step by step and needle by needle.
#[derive(Default)]
struct Findings(Vec<Finding>);

impl Findings {
    /// Run `step` watched for `needles`, none of which it may leave behind.
    fn watch<T>(&mut self, label: &str, needles: &[Vec<u8>], step: impl FnOnce() -> T) -> T {
        self.watch_pinned(label, needles, &vec![0; needles.len()], step)
    }

    /// Run `step` watched for `needles`, each of which it leaves behind in
    /// exactly as many freed blocks as `pinned` says OpenMLS does.
    fn watch_pinned<T>(
        &mut self,
        label: &str,
        needles: &[Vec<u8>],
        pinned: &[usize],
        step: impl FnOnce() -> T,
    ) -> T {
        assert!(needles.len() <= MAX_NEEDLES && needles.len() == pinned.len());
        *NEEDLES.lock().unwrap() = needles.to_vec();
        for count in &UNWIPED {
            count.store(0, Ordering::SeqCst);
        }
        ARMED.store(true, Ordering::SeqCst);
        let out = step();
        ARMED.store(false, Ordering::SeqCst);
        let mut total = 0;
        for (needle, &pinned) in pinned.iter().enumerate() {
            let found = UNWIPED[needle].load(Ordering::SeqCst);
            total += found;
            self.0.push(Finding {
                label: label.to_string(),
                needle,
                found,
                pinned,
            });
        }
        println!("LIFECYCLE {label}: {total}");
        out
    }

    fn unwiped(&self) -> Vec<String> {
        self.0
            .iter()
            .filter(|f| f.found != f.pinned)
            .map(|f| {
                let Finding {
                    label,
                    needle,
                    found,
                    pinned,
                } = f;
                if found > pinned {
                    format!(
                        "{label}: {found} freed blocks held needle {needle}, \
                         {pinned} of them OpenMLS's own"
                    )
                } else {
                    format!(
                        "{label}: {found} freed blocks held needle {needle}, fewer than \
                         the {pinned} OpenMLS is pinned to leave: move the pin"
                    )
                }
            })
            .collect()
    }
}

const G: &[u8] = b"3f0d9c1e-6a2b-4c7d-8e5f-0a1b2c3d4e5f";
const ID: &str = "0b7e5a52-3c1d-4f2e-9a8b-7c6d5e4f3a2b";
const MAILBOX_MESSAGE: u8 = 1;
/// The words of the message kept and released: no zero byte, so a wiped
/// block cannot match.
const WORDS: &[u8] = b"lifecycle-needle: the words of a kept message";
/// The words of a message in a later epoch, opened and not kept.
const LATER: &[u8] = b"lifecycle-needle: words opened, not kept";
const HELD: usize = 30;

/// An in-memory store that refuses to keep an opened message: the message
/// opens, then the core refuses it.
#[derive(Debug)]
struct RefusesKeeps(MemoryKv);

impl KvStore for RefusesKeeps {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        self.0.get(key)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        if key
            .windows(b"opened_content".len())
            .any(|w| w == b"opened_content")
        {
            return Err(KvError::new("refusing a keep"));
        }
        self.0.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        self.0.delete(key)
    }
    fn scan(&self, prefix: &[u8]) -> Result<Vec<KvEntry>, KvError> {
        self.0.scan(prefix)
    }
    fn flush(&self) -> Result<(), KvError> {
        self.0.flush()
    }
    fn rollback(&self) -> Result<(), KvError> {
        self.0.rollback()
    }
}

/// The two stores a client runs on.
#[derive(Clone, Copy)]
enum Store {
    Sqlite,
    InMemory,
}

impl Store {
    fn name(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::InMemory => "in-memory",
        }
    }

    fn open(self, tag: &str) -> PeachyStorage {
        match self {
            Self::InMemory => PeachyStorage::in_memory(),
            Self::Sqlite => {
                let path = std::env::temp_dir().join(format!(
                    "peachy-lifecycle-wipe-{tag}-{}.sqlite",
                    std::process::id()
                ));
                for suffix in ["", "-wal", "-shm"] {
                    let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
                }
                PeachyStorage::open(Box::new(SqliteKv::open(&path).unwrap())).unwrap()
            }
        }
    }
}

fn envelope_secret(client: &Client) -> Vec<u8> {
    client
        .export_secret(G, EPOCH_ENVELOPE_EXPORTER_LABEL, G, 32)
        .unwrap()
}

fn key_of(tag: u8) -> Vec<u8> {
    peachy_mls_core::issuer::device_key_pair(&device_seed(tag))
        .1
        .to_vec()
}

/// A resendable message `sender` seals to the group, with the seal it makes
/// for the device whose key is `to`.
fn sent(sender: &mut Client, text: &str, to: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let frame = [
        vec![0xFF, 0x01],
        format!(r#"{{"i":"{ID}","t":"{text}"}}"#).into_bytes(),
    ]
    .concat();
    let message = sender
        .encrypt_with_hint(G, &frame, CONTENT_HINT_RESENDABLE)
        .unwrap();
    let envelope = sender
        .seal_envelope(G, ENVELOPE_KIND_MESSAGE, &message)
        .unwrap();
    let seal = sender
        .device_seals(G, &envelope)
        .unwrap()
        .into_iter()
        .find(|(key, _)| key == to)
        .unwrap()
        .1;
    (envelope, seal)
}

/// Bo, on `store`: joined by a Welcome, a message kept and released, and
/// four commits, two of its own and two of Ada's. Answers Bo and every
/// secret Bo was done with.
fn member_life(store: Store, found: &mut Findings) -> (Client, Vec<Vec<u8>>) {
    let s = issuer();
    let label = store.name();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client_on(&s, 2, "actor-bo", "device-bo", store.open("bo"));
    ada.create_group(G).unwrap();
    let kp = bo.generate_key_package().unwrap();
    let added = ada.add_member(G, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.join_from_welcome(&added.welcome.unwrap()).unwrap();

    // A MESSAGE ENCRYPTED, OPENED AND KEPT UNDER ITS MAILBOX ID, THEN
    // RELEASED.
    let words = [WORDS.to_vec()];
    let message = found.watch_pinned(
        &format!("{label}: Ada encrypts the words"),
        &words,
        &[OPENMLS_ENCRYPT_COPIES],
        || ada.encrypt(G, WORDS).unwrap(),
    );
    let opened = found.watch_pinned(
        &format!("{label}: Bo opens and keeps the words"),
        &words,
        &[OPENMLS_DECRYPT_COPIES],
        || bo.process_message_as(G, &message, "env-kept").unwrap(),
    );
    match opened {
        Incoming::Application { mut plaintext, .. } => {
            assert_eq!(plaintext, WORDS);
            // The caller's copy is the caller's to wipe.
            plaintext.zeroize();
        }
        other => panic!("{other:?}"),
    }
    let released = found.watch(&format!("{label}: release_opened"), &words, || {
        bo.release_opened("env-kept").unwrap()
    });
    assert!(released, "the message was kept, and is let go");

    // COMMITS: each epoch left behind, the one the Welcome seated Bo in
    // first, is a needle from the next commit on.
    let mut past: Vec<Vec<u8>> = Vec::new();
    let mut leaving = envelope_secret(&bo);
    for n in 0..4 {
        let needles = past.clone();
        if n % 2 == 0 {
            found.watch(&format!("{label}: own commit {n}"), &needles, || {
                let bundle = bo.self_update(G).unwrap();
                bo.merge_pending_commit(G).unwrap();
                ada.process_commit(G, &bundle.commit).unwrap();
            });
        } else {
            let bundle = ada.self_update(G).unwrap();
            ada.merge_pending_commit(G).unwrap();
            found.watch(&format!("{label}: Ada's commit {n}"), &needles, || {
                bo.process_commit(G, &bundle.commit).unwrap();
            });
        }
        past.push(std::mem::replace(&mut leaving, envelope_secret(&bo)));
    }
    // A message in the latest epoch, opened and not kept: its words are
    // the caller's, and no past epoch is left behind.
    let message = ada.encrypt(G, LATER).unwrap();
    let mut needles = past.clone();
    needles.push(LATER.to_vec());
    let mut pinned = vec![0; past.len()];
    pinned.push(OPENMLS_DECRYPT_COPIES);
    found.watch_pinned(
        &format!("{label}: a message in a later epoch"),
        &needles,
        &pinned,
        || match bo.process_message(G, &message).unwrap() {
            Incoming::Application { mut plaintext, .. } => {
                assert_eq!(plaintext, LATER);
                plaintext.zeroize();
            }
            other => panic!("{other:?}"),
        },
    );
    past.push(leaving);
    past.push(WORDS.to_vec());
    past.push(LATER.to_vec());
    (bo, past)
}

/// Cy, on `store`: forked, holding [`HELD`] of Ada's envelopes on their
/// device seals, reseated, and handed each out on its seal's grant, opened
/// on it and released. Answers Cy and the seal's secret.
fn held_life(store: Store, found: &mut Findings) -> (Client, Vec<u8>) {
    let s = issuer();
    let label = store.name();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client_on(&s, 3, "actor-cy", "device-cy", store.open("cy"));
    ada.create_group(G).unwrap();
    {
        let mut others: [&mut Client; 2] = [&mut bo, &mut cy];
        for i in 0..others.len() {
            let kp = others[i].generate_key_package().unwrap();
            let b = ada.add_member(G, &kp).unwrap();
            ada.merge_pending_commit(G).unwrap();
            for x in others.iter_mut().take(i) {
                x.process_commit(G, &b.commit).unwrap();
            }
            others[i].join_from_welcome(&b.welcome.unwrap()).unwrap();
        }
    }
    // Reseated with no gap handed back: the envelopes open only on their
    // seals' grants.
    ada.act_as_member_handing_back_no_gap();
    cy.self_update(G).unwrap();
    cy.merge_pending_commit(G).unwrap();
    let main_line = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &main_line.commit).unwrap();

    let secret = envelope_secret(&ada);
    let needles = vec![secret.clone()];
    let at = u64::try_from(NOW * 1000).unwrap();
    let sends: Vec<(Vec<u8>, Vec<u8>)> = (0..HELD)
        .map(|n| sent(&mut ada, &format!("missed {n}"), &key_of(3)))
        .collect();
    found.watch(
        &format!("{label}: {HELD} held on their seals"),
        &needles,
        || {
            for (n, (envelope, seal)) in sends.iter().enumerate() {
                let kept = cy
                    .hold_envelope_sealed(
                        MAILBOX_MESSAGE,
                        &format!("env-{n:03}"),
                        at + n as u64,
                        envelope,
                        seal,
                    )
                    .unwrap();
                assert!(kept.is_kept(), "held {n}");
            }
        },
    );
    found.watch(&format!("{label}: a pass that waits"), &needles, || {
        assert!(
            cy.next_reopenable().unwrap().is_none(),
            "the copy is the fork"
        );
    });

    // THE RESEAT.
    let kp = found.watch(&format!("{label}: forget the fork"), &needles, || {
        cy.forget_group(G).unwrap();
        cy.generate_key_package().unwrap()
    });
    let cy_leaf = ada.leaf_of_device(G, "device-cy").unwrap();
    let back = ada.replace_member(G, cy_leaf, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &back.commit).unwrap();
    found.watch(&format!("{label}: rejoin"), &needles, || {
        cy.join_from_welcome(&back.welcome.unwrap()).unwrap();
    });

    // EACH HANDED OUT ON ITS GRANT, OPENED ON IT, AND RELEASED.
    let handed = found.watch(
        &format!("{label}: handed out, opened, released"),
        &needles,
        || {
            let mut handed = 0;
            while let Some(held) = cy.next_reopenable().unwrap() {
                assert!(
                    cy.open_envelope(&held.envelope).unwrap().is_some(),
                    "opens on its grant"
                );
                assert!(cy.release_held(&held.id).unwrap());
                handed += 1;
            }
            handed
        },
    );
    assert_eq!(handed, HELD, "every envelope held was handed out");

    // ONE THAT OPENS AT ONCE: not kept, and what it opened to is wiped.
    let inner = ada.encrypt(G, WORDS).unwrap();
    let envelope = ada.seal_envelope(G, ENVELOPE_KIND_MESSAGE, &inner).unwrap();
    let kept = found.watch(
        &format!("{label}: held, and opens at once"),
        &[secret.clone(), inner],
        || {
            cy.hold_envelope_sealed(MAILBOX_MESSAGE, "env-now", at + HELD as u64, &envelope, &[])
                .unwrap()
        },
    );
    assert!(!kept.is_kept(), "it opens now: nothing to hold");
    (cy, secret)
}

/// Both lives on `store`, then each client dropped with every needle.
fn life(store: Store, found: &mut Findings) {
    let (bo, mut needles) = member_life(store, found);
    let (cy, seal_secret) = held_life(store, found);
    needles.push(seal_secret);
    let label = store.name();
    found.watch(&format!("{label}: drop"), &needles, || {
        drop(bo);
        drop(cy);
    });
}

#[test]
fn a_whole_life_frees_no_secret_unwiped() {
    let mut found = Findings::default();

    // The instrument: an unwiped copy of a needle, freed while watched, is
    // seen.
    let copy = Box::new(*b"lifecycle-instrument-check-0123456789");
    found.watch("instrument", &[copy.to_vec()], || {
        drop(std::hint::black_box(copy));
    });
    assert_eq!(found.0[0].found, 1, "the instrument sees an unwiped copy");
    found.0.clear();

    // The in-memory store on its own: a value replaced, deleted, rolled back
    // and dropped with the store, and its Debug.
    let kv = MemoryKv::new();
    let value = b"lifecycle-needle: a stored value, wiped".to_vec();
    kv.put(b"k", &value).unwrap();
    kv.flush().unwrap();
    let printed = format!("{kv:?}");
    found.watch(
        "in-memory store: replace, delete, rollback, drop",
        std::slice::from_ref(&value),
        || {
            kv.put(b"k", b"other").unwrap();
            kv.put(b"j", &value).unwrap();
            kv.flush().unwrap();
            kv.delete(b"j").unwrap();
            kv.rollback().unwrap();
            kv.delete(b"j").unwrap();
            kv.flush().unwrap();
            kv.put(b"i", &value).unwrap();
            kv.flush().unwrap();
            drop(kv);
        },
    );
    let spelled = format!("{value:?}");
    assert!(
        !printed.contains(&spelled[1..spelled.len() - 1]),
        "the in-memory store's Debug prints a value: {printed}"
    );

    // An envelope's inner bytes, sealed and opened in each version: the
    // padded plaintext the AEAD seals and the one it opens are wiped, and the
    // copy handed back is the caller's.
    let inner = b"lifecycle-needle: a seat ask's inner bytes".to_vec();
    let epoch = [7u8; 32];
    found.watch(
        "an envelope sealed and opened, each version",
        std::slice::from_ref(&inner),
        || {
            for kind in [ENVELOPE_KIND_SEAT_ASK, ENVELOPE_KIND_LINK_PREVIEW] {
                let sealed = seal_group_id_envelope(G, kind, &inner).unwrap();
                let mut opened = open_envelope_for(G, &sealed).unwrap();
                assert_eq!(opened.inner, inner);
                opened.inner.zeroize();
            }
            let sealed = seal_epoch_envelope(&epoch, ENVELOPE_KIND_SEAT_ASK, &inner).unwrap();
            let (_, opened) = open_epoch_envelope(&epoch, &sealed).unwrap();
            assert_eq!(*opened, inner);
        },
    );

    // A live call frame's signal, sealed and opened: the padded plaintexts
    // are wiped, and what is handed back is the caller's. (A typing frame
    // carries no secret and is not watched.)
    let signal = b"lifecycle-needle: a live call frame's signal".to_vec();
    found.watch(
        "a live call frame, sealed and opened",
        std::slice::from_ref(&signal),
        || {
            let stamp = LiveStamp {
                sender_leaf: 1,
                sent_at_ms: 2,
            };
            let sealed = seal_live_frame(&epoch, stamp, &signal).unwrap();
            let (_, mut opened) = open_live_frame(&epoch, &sealed).unwrap();
            assert_eq!(opened, signal);
            opened.zeroize();
        },
    );

    // An application message's Debug gives its length, not its words.
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    ada.create_group(G).unwrap();
    let kp = bo.generate_key_package().unwrap();
    let added = ada.add_member(G, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.join_from_welcome(&added.welcome.unwrap()).unwrap();
    let incoming = bo
        .process_message(G, &ada.encrypt(G, WORDS).unwrap())
        .unwrap();
    let printed = format!("{incoming:?} {incoming:#?}");
    let spelled = format!("{:?}", WORDS.to_vec());
    assert!(
        printed.contains("plaintext_len") && !printed.contains(&spelled[1..spelled.len() - 1]),
        "a message's Debug prints its words: {printed}"
    );
    drop((ada, bo, incoming));

    // A message refused after it opened (its keep refused by the store): the
    // core wipes its own copy of the words, so only OpenMLS's are left.
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let refusing = PeachyStorage::open(Box::new(RefusesKeeps(MemoryKv::new()))).unwrap();
    let mut bo = client_on(&s, 2, "actor-bo", "device-bo", refusing);
    ada.create_group(G).unwrap();
    let kp = bo.generate_key_package().unwrap();
    let added = ada.add_member(G, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.join_from_welcome(&added.welcome.unwrap()).unwrap();
    let message = ada.encrypt(G, WORDS).unwrap();
    let refused = found.watch_pinned(
        "a message refused after it opened",
        &[WORDS.to_vec()],
        &[OPENMLS_DECRYPT_COPIES],
        || bo.process_message_as(G, &message, "env-refused").is_err(),
    );
    assert!(
        refused,
        "the store refused the keep, and the message with it"
    );
    drop((ada, bo));

    // A removed member's message, sealed at the epoch it was removed from:
    // it opens, then is refused for its sender, and the core's copy of the
    // words drops wiped, so only OpenMLS's are left.
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
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
    let cy_leaf = ada.leaf_of_device(G, "device-cy").unwrap();
    let removal = ada.remove_leaf(G, cy_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
    let message = cy.encrypt(G, WORDS).unwrap();
    let refused = found.watch_pinned(
        "a removed member's message",
        &[WORDS.to_vec()],
        &[OPENMLS_DECRYPT_COPIES],
        || bo.process_message(G, &message),
    );
    assert!(
        matches!(refused, Err(Error::NotFromAMember(_))),
        "{refused:?}"
    );
    drop((ada, bo, cy));

    life(Store::Sqlite, &mut found);
    life(Store::InMemory, &mut found);

    let unwiped = found.unwiped();
    assert!(
        unwiped.is_empty(),
        "these steps freed a secret unwiped:\n{}",
        unwiped.join("\n")
    );
}
