// SPDX-License-Identifier: MIT
//! WHAT A MESSAGE OPENED TO IS KEPT WITH THE KEY IT SPENT
//! (`Client::process_message_as`, `Client::release_opened`).
//!
//! Opening a message spends its ratchet key, and the client stores what it
//! said only after the core answers. A process that died between the two (a
//! phone killing an app mid-drain), or a store that refused the client's
//! write, left a message whose key was gone and whose words were nowhere: the
//! mailbox handed the envelope over again, and it read as a duplicate.
//!
//! These hold that the words are written in the same write that spends the
//! key: the envelope handed over again, after a restart over the same store,
//! answers what it opened to the first time, until the client releases it;
//! and a keep that cannot be written spends nothing.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use peachy_mls_core::issuer::TestIssuer;
use peachy_mls_core::{
    Client, Error, Incoming, KvEntry, KvError, KvStore, MemoryKv, PeachyStorage,
};
use support::{advance_ms, client, client_on, issuer};

const GROUP: &[u8] = b"00000000-0000-4000-8000-00000000c0de";

/// A store that refuses writes of the opened-message records while `fail`
/// is set, and every other write as it comes; it counts the erases the
/// client asks of it.
#[derive(Debug, Clone)]
struct RefusingKv {
    inner: MemoryKv,
    fail: Arc<AtomicBool>,
    erased: Arc<AtomicUsize>,
}

impl RefusingKv {
    fn write(&self, key: &[u8]) -> Result<(), KvError> {
        let kept = key.windows(14).any(|w| w == b"opened_content");
        if kept && self.fail.load(Ordering::SeqCst) {
            return Err(KvError::new("injected: disk full"));
        }
        Ok(())
    }
}

impl KvStore for RefusingKv {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        self.inner.get(key)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        self.write(key)?;
        self.inner.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        self.write(key)?;
        self.inner.delete(key)
    }
    fn scan(&self, prefix: &[u8]) -> Result<Vec<KvEntry>, KvError> {
        self.inner.scan(prefix)
    }
    fn flush(&self) -> Result<(), KvError> {
        self.inner.flush()
    }
    fn rollback(&self) -> Result<(), KvError> {
        self.inner.rollback()
    }
    fn erase_superseded(&self) -> Result<bool, KvError> {
        self.erased.fetch_add(1, Ordering::SeqCst);
        self.inner.erase_superseded()
    }
}

fn bo_on(server: &TestIssuer, kv: &RefusingKv) -> Client {
    client_on(
        server,
        2,
        "actor-bo",
        "device-bo",
        PeachyStorage::open(Box::new(kv.clone())).expect("store"),
    )
}

fn pair(server: &TestIssuer, kv: &RefusingKv) -> (Client, Client) {
    let mut ada = client(server, 1, "actor-ada", "device-ada");
    let mut bo = bo_on(server, kv);
    ada.create_group(GROUP).expect("create");
    let kp = bo.generate_key_package().expect("key package");
    let added = ada.add_member(GROUP, &kp).expect("add");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&added.welcome.expect("welcome"))
        .expect("join");
    (ada, bo)
}

fn store() -> RefusingKv {
    RefusingKv {
        inner: MemoryKv::default(),
        fail: Arc::new(AtomicBool::new(false)),
        erased: Arc::new(AtomicUsize::new(0)),
    }
}

fn words(incoming: Incoming) -> (String, Vec<u8>) {
    match incoming {
        Incoming::Application {
            sender, plaintext, ..
        } => (sender.actor_id, plaintext),
        other => panic!("not an application message: {other:?}"),
    }
}

/// The app opened a message and died before it stored it. Started again
/// over the same store, the same envelope answers the same words from the
/// same sender, as often as it is handed over, until the client releases it.
#[test]
fn an_envelope_opened_by_a_run_that_died_answers_its_words_again() {
    let server = issuer();
    let kv = store();
    let (mut ada, mut bo) = pair(&server, &kv);
    let m = ada.encrypt(GROUP, b"dinner at eight").expect("encrypt");
    assert_eq!(
        words(bo.process_message_as(GROUP, &m, "env-1").expect("opens")),
        ("actor-ada".to_owned(), b"dinner at eight".to_vec())
    );
    drop(bo); // the process dies before the archive write

    let mut bo = bo_on(&server, &kv);
    // The bare door: the key is spent, and the message is a duplicate.
    assert!(matches!(
        bo.process_message(GROUP, &m),
        Err(Error::Duplicate(_))
    ));
    // Under its envelope id: the words, twice over.
    for _ in 0..2 {
        assert_eq!(
            words(bo.process_message_as(GROUP, &m, "env-1").expect("kept")),
            ("actor-ada".to_owned(), b"dinner at eight".to_vec())
        );
    }

    // Stored by the client: released, and the record is gone.
    assert!(bo.release_opened("env-1").expect("release"));
    assert!(!bo.release_opened("env-1").expect("nothing left"));
    assert!(matches!(
        bo.process_message_as(GROUP, &m, "env-1"),
        Err(Error::Duplicate(_))
    ));

    // The ratchet went on all along: the next message opens.
    let next = ada.encrypt(GROUP, b"next").expect("encrypt");
    assert_eq!(
        words(bo.process_message_as(GROUP, &next, "env-2").expect("opens")).1,
        b"next"
    );
}

/// The record answers only the bytes it was kept for, in the group it was
/// kept in: another message under a reused id, or the same id named for
/// another group, goes through the door as any other.
#[test]
fn a_record_answers_only_its_own_message() {
    let server = issuer();
    let kv = store();
    let (mut ada, mut bo) = pair(&server, &kv);
    let first = ada.encrypt(GROUP, b"first").expect("encrypt");
    let second = ada.encrypt(GROUP, b"second").expect("encrypt");
    words(
        bo.process_message_as(GROUP, &first, "env-x")
            .expect("opens"),
    );
    assert_eq!(
        words(
            bo.process_message_as(GROUP, &second, "env-x")
                .expect("opens")
        )
        .1,
        b"second"
    );
    assert!(bo
        .process_message_as(b"another group", &second, "env-x")
        .is_err());
    // An empty id keeps nothing, and neither does one holding a NUL.
    let third = ada.encrypt(GROUP, b"third").expect("encrypt");
    words(bo.process_message_as(GROUP, &third, "").expect("opens"));
    assert!(!bo.release_opened("").expect("nothing"));
    let fourth = ada.encrypt(GROUP, b"fourth").expect("encrypt");
    words(
        bo.process_message_as(GROUP, &fourth, "env\0y")
            .expect("opens"),
    );
    assert!(!bo.release_opened("env\0y").expect("nothing"));
}

/// AN ID HANDED OUT AGAIN NEVER OVERWRITES WHAT IT KEPT: a server reusing an
/// envelope id for another message, while the first is still held, keeps
/// the second's words beside the first's. Each answers its own; one release
/// lets both go.
#[test]
fn a_reused_id_keeps_both_messages_words() {
    let server = issuer();
    let kv = store();
    let (mut ada, mut bo) = pair(&server, &kv);
    let first = ada.encrypt(GROUP, b"first").expect("encrypt");
    let second = ada.encrypt(GROUP, b"second").expect("encrypt");
    words(
        bo.process_message_as(GROUP, &first, "env-x")
            .expect("opens"),
    );
    words(
        bo.process_message_as(GROUP, &second, "env-x")
            .expect("opens"),
    );
    drop(bo);

    let mut bo = bo_on(&server, &kv);
    assert_eq!(
        words(bo.process_message_as(GROUP, &first, "env-x").expect("kept")).1,
        b"first"
    );
    assert_eq!(
        words(
            bo.process_message_as(GROUP, &second, "env-x")
                .expect("kept")
        )
        .1,
        b"second"
    );
    assert!(bo.release_opened("env-x").expect("release"));
    for m in [&first, &second] {
        assert!(matches!(
            bo.process_message_as(GROUP, m, "env-x"),
            Err(Error::Duplicate(_))
        ));
    }
}

/// A RELEASE ERASES: the words are plaintext the client's own store may
/// already have let go (a disappearing message), so the write that deletes
/// them also erases what it freed, as every write that deletes a secret
/// does. Without it, the page held them until the next message.
#[test]
fn a_release_erases_what_it_freed() {
    let server = issuer();
    let kv = store();
    let (mut ada, mut bo) = pair(&server, &kv);
    let m = ada.encrypt(GROUP, b"gone soon").expect("encrypt");
    words(bo.process_message_as(GROUP, &m, "env-1").expect("opens"));
    let before = kv.erased.load(Ordering::SeqCst);
    assert!(bo.release_opened("env-1").expect("release"));
    assert!(
        kv.erased.load(Ordering::SeqCst) > before,
        "the release ends erased"
    );
}

/// A PAGE'S RELEASES ARE ONE WRITE: every envelope it acknowledges lets its
/// words go in a single write that ends with a single erase, not one per
/// envelope. Ids that keep nothing (unknown, empty, holding a NUL) are passed
/// over, and none at all writes nothing.
#[test]
fn a_page_releases_its_envelopes_in_one_write() {
    let server = issuer();
    let kv = store();
    let (mut ada, mut bo) = pair(&server, &kv);
    let ids = ["env-1", "env-2", "env-3"];
    let mut sent = Vec::new();
    for (n, id) in ids.iter().enumerate() {
        let m = ada
            .encrypt(GROUP, format!("message {n}").as_bytes())
            .expect("encrypt");
        words(bo.process_message_as(GROUP, &m, id).expect("opens"));
        sent.push(m);
    }
    let before = kv.erased.load(Ordering::SeqCst);
    assert_eq!(
        bo.release_opened_all(&["env-1", "env-2", "env-3", "env-unknown", "", "env\0y"])
            .expect("release"),
        3
    );
    assert_eq!(
        kv.erased.load(Ordering::SeqCst) - before,
        1,
        "one erase for the page"
    );
    for (m, id) in sent.iter().zip(ids) {
        assert!(matches!(
            bo.process_message_as(GROUP, m, id),
            Err(Error::Duplicate(_))
        ));
    }
    let before = kv.erased.load(Ordering::SeqCst);
    assert_eq!(bo.release_opened_all(&ids).expect("nothing left"), 0);
    assert_eq!(bo.release_opened_all(&[]).expect("nothing"), 0);
    assert_eq!(
        kv.erased.load(Ordering::SeqCst),
        before,
        "nothing held, nothing written"
    );
}

/// A CLIENT THAT LIVES FOR WEEKS STILL SWEEPS: a record its client never
/// released goes once it is past the 30-day hold, at a keep an hour or more
/// after the last sweep, not only at the first keep of the client's life.
#[test]
fn a_long_lived_client_sweeps_what_it_never_released() {
    let server = issuer();
    let kv = store();
    let (mut ada, mut bo) = pair(&server, &kv);
    let old = ada.encrypt(GROUP, b"never stored").expect("encrypt");
    words(
        bo.process_message_as(GROUP, &old, "env-old")
            .expect("opens"),
    );

    advance_ms(31 * 24 * 60 * 60 * 1000);
    // Ada's leaf lapsed with the month: she renews before she says more.
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&support::device_seed(1));
    let now = support::NOW + 31 * support::DAY;
    let token = server
        .issue(
            "actor-ada",
            "device-ada",
            &public,
            now - support::HOUR,
            now + 30 * support::DAY,
        )
        .expect("mint");
    ada.update_credential(&token, None)
        .expect("fresh credential");
    let renewal = ada.refresh_credential(GROUP).expect("renew");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &renewal.commit)
        .expect("bo takes the renewal");
    let later = ada.encrypt(GROUP, b"a month on").expect("encrypt");
    words(
        bo.process_message_as(GROUP, &later, "env-new")
            .expect("opens"),
    );

    assert!(matches!(
        bo.process_message_as(GROUP, &old, "env-old"),
        Err(Error::Duplicate(_))
    ));
    assert_eq!(
        words(
            bo.process_message_as(GROUP, &later, "env-new")
                .expect("kept")
        )
        .1,
        b"a month on"
    );
}

/// A KEEP THAT CANNOT BE WRITTEN SPENDS NOTHING: the message is refused as a
/// failed step of the door, the key is still there, and the same message
/// opens once the store takes writes again. Without it, a refused keep had
/// spent the key with nothing to show for it.
#[test]
fn a_keep_that_is_not_written_spends_nothing() {
    let server = issuer();
    let kv = store();
    let (mut ada, mut bo) = pair(&server, &kv);
    let m = ada.encrypt(GROUP, b"hold this").expect("encrypt");

    kv.fail.store(true, Ordering::SeqCst);
    assert!(
        bo.process_message_as(GROUP, &m, "env-1").is_err(),
        "the refused keep is reported"
    );
    kv.fail.store(false, Ordering::SeqCst);

    // Not a duplicate: the message never counted as opened.
    assert_eq!(
        words(bo.process_message_as(GROUP, &m, "env-1").expect("opens")).1,
        b"hold this"
    );
    // And the same holds across a restart.
    drop(bo);
    let mut bo = bo_on(&server, &kv);
    assert_eq!(
        words(bo.process_message_as(GROUP, &m, "env-1").expect("kept")).1,
        b"hold this"
    );
}

/// An own message's echo keeps nothing: there was nothing to open.
#[test]
fn an_echo_keeps_nothing() {
    let server = issuer();
    let kv = store();
    let (mut ada, mut bo) = pair(&server, &kv);
    let mine = bo.encrypt(GROUP, b"from bo").expect("encrypt");
    assert!(matches!(
        bo.process_message_as(GROUP, &mine, "env-own")
            .expect("echo"),
        Incoming::Echo
    ));
    assert!(!bo.release_opened("env-own").expect("nothing kept"));
    words(
        ada.process_message_as(GROUP, &mine, "env-own")
            .expect("opens"),
    );
}
