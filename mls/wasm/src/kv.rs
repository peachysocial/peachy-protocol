// SPDX-License-Identifier: MIT
//! A [`KvStore`] that answers from memory and remembers what it owes the host.
//!
//! ## Why this exists at all
//!
//! OpenMLS' `StorageProvider` is **synchronous**. Every method — `write_tree`,
//! `read_epoch_key_pairs`, `delete_key_package` — returns a value, not a future,
//! and it is called from deep inside OpenMLS while it is halfway through
//! building a commit. There is no seam to `await` in, and there will not be one:
//! making it async would make every OpenMLS entry point async, in a library
//! whose other three targets have blocking storage.
//!
//! IndexedDB, the only durable store a browser tab actually has, is
//! **asynchronous** and has no synchronous door. (Neither does the Origin
//! Private File System outside a worker, and `localStorage` — the one
//! synchronous store — is ~5 MB of UTF-16 strings shared with everything else
//! the origin does, which is not where a ratchet tree goes.)
//!
//! So the two cannot meet directly, and any binding that says otherwise is
//! lying about one of them. What this does instead:
//!
//! - **At open**, the whole store is read out of IndexedDB in one async pass
//!   and held in a `BTreeMap`. That is what `MlsClient.open()` awaits.
//! - **During an operation**, every OpenMLS read and write hits that map, with
//!   no I/O at all. Writes and deletes are also recorded in a *dirty* set.
//! - **After an operation**, `await client.flush()` hands the WHOLE dirty set
//!   to the host as one `writeBatch` call, and clears it once the host says it
//!   landed. One call, because the host writes it in one transaction: see
//!   "never half of one" below, which is a promise only an atomic write keeps.
//!
//! ## The window this leaves, stated plainly
//!
//! Between a mutating call returning and its `flush()` promise resolving, the
//! new state exists only in this map. A tab closed in that window loses it.
//!
//! What that costs is bounded, and it is the same shape as the SQLite backend's
//! window (`peachy_mls_core::sqlite`): a lost flush loses the LAST operation
//! whole, never half of one, because the dirty set goes over in ONE
//! `writeBatch` call that the host applies in one transaction, and a batch
//! that fails to write stays dirty in its entirety. The concrete failures are the ordinary
//! MLS ones — a commit the group accepted that this device did not keep (it
//! recovers by processing its own commit back from the delivery service as any
//! other member would), or a key package published whose private half was not
//! kept (that Welcome cannot be opened, and the key package has to be
//! republished). Neither is silent corruption.
//!
//! The way to keep the window small is to `await flush()` before telling the
//! delivery service anything, which is what a caller should do anyway: the
//! commit is not real until the server has it, and the server having a commit
//! this device cannot decrypt is the state worth avoiding.
//!
//! ## How much memory
//!
//! All of it, for one device's groups. An MLS group's stored state is a ratchet
//! tree, a group context, the current epoch's secrets and whatever proposals
//! are queued — kilobytes per group, not megabytes — and a browser tab that
//! cannot hold its own chat list's key material has a bigger problem. If that
//! ever stops being true the fix is a partial hydration keyed by group id,
//! which is why `scan` takes a prefix and why the key layout puts the namespace
//! before the group id.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use peachy_mls_core::{KvEntry, KvError, KvStore};
use zeroize::Zeroizing;

/// A stored value: epoch secrets, key-pair private halves and the opened
/// plaintexts the core keeps are among them, so every copy the cache holds
/// (in the map, in what it owes the host, in what a rollback would put back)
/// is wiped when it is replaced or dropped.
pub type Value = Zeroizing<Vec<u8>>;

/// One pending write. `None` is a delete — the distinction has to survive to
/// the host, because "absent from the map" and "explicitly removed" are the
/// same state in memory and very different statements to make to IndexedDB.
pub type Pending = (Vec<u8>, Option<Value>);

#[derive(Default)]
struct Cached {
    entries: BTreeMap<Vec<u8>, Value>,
    dirty: BTreeMap<Vec<u8>, Option<Value>>,
    /// For each key written since the core's last flush (the end of the last
    /// operation), what the map and the dirty set held for it before that
    /// first write: what [`KvStore::rollback`] puts back when an operation
    /// fails part-way. Cleared by every flush.
    undo: BTreeMap<Vec<u8>, Undo>,
}

/// One key's state before the operation touched it: its value (`None`:
/// absent) and what was owed to the host for it (`None`: nothing).
type Undo = (Option<Value>, Option<Option<Value>>);

impl Cached {
    fn note_undo(&mut self, key: &[u8]) {
        if !self.undo.contains_key(key) {
            let before = (self.entries.get(key).cloned(), self.dirty.get(key).cloned());
            self.undo.insert(key.to_vec(), before);
        }
    }
}

/// A write-through cache over an async host. See the module header.
///
/// `Clone` shares the map and the dirty set: the clone handed to
/// [`peachy_mls_core::PeachyStorage`] and the one the binding keeps for
/// flushing are two handles on one store, not two stores.
#[derive(Clone, Default)]
pub struct CacheKv {
    inner: Arc<Mutex<Cached>>,
}

/// Counts only: the values are secrets.
impl std::fmt::Debug for CacheKv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cached = self.locked();
        f.debug_struct("CacheKv")
            .field("entries", &cached.entries.len())
            .field("pending", &cached.dirty.len())
            .finish_non_exhaustive()
    }
}

impl CacheKv {
    /// A cache primed with what the host already held.
    ///
    /// Nothing is marked dirty: these entries came FROM the host, and writing
    /// them straight back would turn every open into a full rewrite.
    pub fn hydrated(entries: impl IntoIterator<Item = KvEntry>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Cached {
                // Moved in, not copied: each value is wrapped where it lies.
                entries: entries
                    .into_iter()
                    .map(|(key, value)| (key, Zeroizing::new(value)))
                    .collect(),
                dirty: BTreeMap::new(),
                undo: BTreeMap::new(),
            })),
        }
    }

    /// Everything owed to the host, WITHOUT clearing it.
    ///
    /// In key order, which is not cosmetic: the host writes them in one
    /// IndexedDB transaction, so two devices replaying the same sequence
    /// produce the same sequence of writes and a test can say so.
    ///
    /// **Peeking rather than taking is what makes
    /// [`CacheKv::pending_count`] true.** A drain that *took* the dirty set up
    /// front would leave `pendingWrites` at zero for the whole duration of the
    /// write — the one window it exists to measure — so a caller following the
    /// documented advice ("assert it is zero before you let the tab go") would
    /// read zero because the work had been picked up, not because it had landed.
    pub fn peek_pending(&self) -> Vec<Pending> {
        self.locked()
            .dirty
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    /// The host committed this batch: stop owing exactly these writes.
    ///
    /// A key written AGAIN since the batch was peeked stays owed, compared by
    /// value rather than by presence — dropping it would silently discard a
    /// write the caller has been told nothing about. JS is single-threaded, but
    /// a caller is free to run another operation while a flush promise is in
    /// flight, so "since" is reachable.
    pub fn commit_pending(&self, written: &[Pending]) {
        let mut cached = self.locked();
        for (key, value) in written {
            if cached.dirty.get(key) == Some(value) {
                cached.dirty.remove(key);
            }
        }
    }

    /// How many keys are waiting on the host. For tests and for a caller that
    /// wants to know whether a flush would do anything.
    pub fn pending_count(&self) -> usize {
        self.locked().dirty.len()
    }

    /// A poisoned lock means a panic happened while a previous caller held it.
    /// On wasm there is one thread, so that previous caller was this one; the
    /// map is a plain `BTreeMap` with no invariant a partial write could break,
    /// so taking it back is strictly better than a second panic.
    fn locked(&self) -> MutexGuard<'_, Cached> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl KvStore for CacheKv {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        Ok(self.locked().entries.get(key).map(|value| value.to_vec()))
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        let mut cached = self.locked();
        cached.note_undo(key);
        cached
            .entries
            .insert(key.to_vec(), Zeroizing::new(value.to_vec()));
        cached
            .dirty
            .insert(key.to_vec(), Some(Zeroizing::new(value.to_vec())));
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        let mut cached = self.locked();
        cached.note_undo(key);
        cached.entries.remove(key);
        cached.dirty.insert(key.to_vec(), None);
        Ok(())
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<KvEntry>, KvError> {
        let cached = self.locked();
        Ok(cached
            .entries
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.to_vec()))
            .collect())
    }

    /// A no-op, and deliberately so.
    ///
    /// The core calls this after every mutating operation as its durability
    /// point. Here there is no synchronous way to reach the host, so the only
    /// honest thing to do is nothing and let the dirty set keep growing until
    /// JavaScript drains it with an awaited `MlsClient.flush()`. Returning an
    /// error instead would fail every operation; pretending to write would be
    /// the lie this module exists to avoid.
    ///
    /// It does end the span a rollback undoes: the operation is whole.
    fn flush(&self) -> Result<(), KvError> {
        self.locked().undo.clear();
        Ok(())
    }

    /// Put back every key the failed operation touched, in the map and in
    /// what is owed to the host, so the next drain hands IndexedDB nothing
    /// of it (`peachy_mls_core::storage` §A step that fails part-way).
    fn rollback(&self) -> Result<(), KvError> {
        let mut cached = self.locked();
        for (key, (entry, owed)) in std::mem::take(&mut cached.undo) {
            match entry {
                Some(value) => cached.entries.insert(key.clone(), value),
                None => cached.entries.remove(&key),
            };
            match owed {
                Some(value) => cached.dirty.insert(key, value),
                None => cached.dirty.remove(&key),
            };
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_write_is_readable_at_once_and_owed_to_the_host() {
        let kv = CacheKv::default();
        kv.put(b"k", b"v").expect("a put into a map");

        assert_eq!(kv.get(b"k").expect("a get"), Some(b"v".to_vec()));
        assert_eq!(kv.pending_count(), 1);

        let batch = kv.peek_pending();
        assert_eq!(
            batch,
            vec![(b"k".to_vec(), Some(Zeroizing::new(b"v".to_vec())))]
        );
        assert_eq!(
            kv.pending_count(),
            1,
            "peeking must not discharge the debt: the host has not written yet",
        );

        kv.commit_pending(&batch);
        assert_eq!(kv.pending_count(), 0, "committing is what clears it");
    }

    #[test]
    fn a_delete_is_owed_to_the_host_as_a_delete() {
        let kv = CacheKv::hydrated([(b"k".to_vec(), b"v".to_vec())]);
        assert_eq!(kv.pending_count(), 0, "hydration owes the host nothing");

        kv.delete(b"k").expect("a delete");
        assert_eq!(kv.get(b"k").expect("a get"), None);
        assert_eq!(kv.peek_pending(), vec![(b"k".to_vec(), None)]);
    }

    /// The whole batch fails or the whole batch lands — the host writes it in
    /// one transaction — so a refusal is simply a `commit_pending` that never
    /// happens, and everything is still owed.
    #[test]
    fn a_refused_flush_leaves_every_key_still_owed() {
        let kv = CacheKv::default();
        kv.put(b"a", b"1").expect("a put");
        kv.put(b"b", b"1").expect("a put");
        let batch = kv.peek_pending();

        // The host refused: nothing is committed.
        assert_eq!(kv.pending_count(), 2);
        assert_eq!(kv.peek_pending(), batch, "the next flush retries all of it");
    }

    #[test]
    fn a_write_made_during_a_flush_stays_owed_after_it() {
        let kv = CacheKv::default();
        kv.put(b"a", b"1").expect("a put");
        kv.put(b"b", b"1").expect("a put");
        let batch = kv.peek_pending();

        // The transaction is in flight, and the caller writes `b` again.
        kv.put(b"b", b"2").expect("a put");
        kv.commit_pending(&batch);

        assert_eq!(
            kv.peek_pending(),
            vec![(b"b".to_vec(), Some(Zeroizing::new(b"2".to_vec())))],
            "b's newer value is still owed; a's committed value is not",
        );
    }

    #[test]
    fn a_scan_is_a_prefix_range_and_stops_at_the_prefix() {
        let kv = CacheKv::hydrated([
            (b"\x01group\x1fone".to_vec(), b"1".to_vec()),
            (b"\x01group\x1ftwo".to_vec(), b"2".to_vec()),
            (b"\x01groupies".to_vec(), b"no".to_vec()),
            (b"\x01tree\x1fone".to_vec(), b"t".to_vec()),
        ]);

        let found = kv.scan(b"\x01group\x1f").expect("a scan");
        assert_eq!(found.len(), 2, "neither `groupies` nor `tree` is in it");
        assert_eq!(found[0].0, b"\x01group\x1fone".to_vec());
    }

    /// A rollback puts back exactly what the failed operation touched: the
    /// values, and what was owed to the host for them, while an earlier
    /// operation's writes still owed stay owed.
    #[test]
    fn a_rollback_undoes_the_operation_and_nothing_before_it() {
        let kv = CacheKv::hydrated([(b"held".to_vec(), b"0".to_vec())]);
        kv.put(b"earlier", b"1").expect("a put");
        kv.flush().expect("the earlier operation ends");

        kv.put(b"held", b"changed").expect("a put");
        kv.put(b"earlier", b"2").expect("a put");
        kv.delete(b"held").expect("a delete");
        kv.put(b"new", b"x").expect("a put");
        kv.rollback().expect("rollback");

        assert_eq!(kv.get(b"held").expect("get"), Some(b"0".to_vec()));
        assert_eq!(kv.get(b"earlier").expect("get"), Some(b"1".to_vec()));
        assert_eq!(kv.get(b"new").expect("get"), None);
        assert_eq!(
            kv.peek_pending(),
            vec![(b"earlier".to_vec(), Some(Zeroizing::new(b"1".to_vec())))],
            "only the earlier operation's write is owed",
        );
    }

    #[test]
    fn the_cache_prints_counts_only() {
        let kv = CacheKv::hydrated([(b"k".to_vec(), b"the stored secret".to_vec())]);
        kv.put(b"j", b"another secret").expect("a put");
        let printed = format!("{kv:?}");
        assert!(printed.contains("entries: 2"), "{printed}");
        assert!(printed.contains("pending: 1"), "{printed}");
        assert!(
            !printed.contains(&format!("{:?}", b"another secret".to_vec())),
            "{printed}"
        );
        assert!(!printed.contains("secret"), "{printed}");
    }

    #[test]
    fn two_handles_are_one_store() {
        let kv = CacheKv::default();
        let other = kv.clone();
        other.put(b"k", b"v").expect("a put through the clone");

        assert_eq!(kv.get(b"k").expect("a get"), Some(b"v".to_vec()));
        assert_eq!(kv.pending_count(), 1);
    }
}
