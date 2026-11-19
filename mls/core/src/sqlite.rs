// SPDX-License-Identifier: MIT
//! The SQLite backend for [`KvStore`]: one table, two columns, one file.
//!
//! What iOS, macOS and Android get, through the C ABI
//! (`peachy_mls_client_open`). The browser gets IndexedDB instead
//! (`mls/wasm`), and a test gets [`MemoryKv`](crate::storage::MemoryKv).
//!
//! ## One table
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS mls_kv (k BLOB PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
//! ```
//!
//! Not a table per entity kind, and not a column per field. The key layout is
//! `mls/core/src/storage.rs`'s business and the values are OpenMLS'
//! `serde_json` — modelling either one in SQL would mean a migration every time
//! OpenMLS changes a struct, which is a migration on every device for a change
//! no Peachy code made. `WITHOUT ROWID` because the key IS the index and a
//! rowid would be a second one; the prefix scan then walks the primary key in
//! order, which is exactly what `scan` promises.
//!
//! ## Durability, and why `flush` is a commit
//!
//! The connection runs in WAL with `synchronous = FULL`, and every write goes
//! into a deferred transaction that [`SqliteKv::flush`] commits. That is the
//! module contract in `storage.rs`, made concrete: one MLS operation is one
//! transaction, so a crash mid-operation rolls the whole thing back rather than
//! leaving a group whose tree advanced and whose epoch secrets did not.
//!
//! A write that FAILS mid-operation (a full disk, an I/O error) does the
//! same. It marks the transaction failed; every later write in it is
//! refused without running, since SQLite may already have rolled the
//! transaction back and a statement run then would autocommit; and whatever
//! closes it next (a flush, the drop) issues `ROLLBACK`, not `COMMIT`
//! (`storage.rs` §A step that fails part-way).
//!
//! `FULL`, in WAL mode: each commit syncs the log before it returns, so an
//! operation whose flush returned survives an OS crash or a power cut, not
//! only a process crash. That is what lets a client acknowledge an envelope
//! once the call that applied it has returned (docs/delivery.md
//! §FetchMailbox and AckMailbox): the delivery service deletes it then, and nothing else
//! holds the commit. A crash before the flush returns loses that operation,
//! whole, while its envelope is still in the mailbox. The cost is one sync of
//! the log per operation, beside the checkpoint's that the erase already runs.
//! `checkpoint_fullfsync = ON` makes a checkpoint on Darwin flush to the
//! medium, not only to the drive's cache; elsewhere it changes nothing.
//!
//! `Drop` commits too, so a client freed without a final flush does not throw
//! away work it already did, unless a write in it failed, which it rolls
//! back. It cannot report a failure — `Drop` has nowhere to
//! put one — which is the second reason [`crate::Client`] flushes explicitly
//! after every operation rather than relying on this.
//!
//! ## Erasing what an operation replaced
//!
//! Forward secrecy on a device is a promise about its storage: once a group
//! has moved to epoch e+1, nothing a seized device yields derives epoch e's
//! secrets (docs/calls.md, N3). WAL mode works against that by
//! design. A commit appends the new pages to the `-wal` file and leaves the
//! old ones where they were, and an ordinary checkpoint copies the newest
//! pages into the main file without clearing the log, so each superseded
//! frame stays on disk, readable under the store key, until a later
//! transaction happens to overwrite it. A client rebuilt from the main file
//! and a prefix of that log is the device as it was one or more epochs ago.
//!
//! So every connection runs with three settings, and the core asks for a
//! fourth after each operation:
//!
//!  - `secure_delete = ON`: a deleted or replaced cell, and a freed page, is
//!    overwritten with zeros, so the main file keeps no old value either.
//!    SQLCipher sets it on a keyed connection already; it is set here on
//!    every connection so the property does not depend on the build.
//!  - `journal_size_limit = 0`: a log that SQLite resets on its own is also
//!    cut to zero bytes, rather than kept at its high-water mark with old
//!    frames past the new write head.
//!  - A truncating checkpoint (`wal_checkpoint(TRUNCATE)`) when the store
//!    opens, which clears a log left by a process that was killed rather
//!    than closed.
//!  - [`SqliteKv::erase_superseded`], the same checkpoint, which
//!    [`crate::Client`] runs after the flush of every operation. Synchronous,
//!    because an app can be suspended or killed at any moment after it
//!    returns, and a deferred one would be skipped exactly then.
//!
//! The checkpoint never waits for another connection. Another process on the
//! same file (a notification extension, say) may be mid-read or mid-write;
//! then the checkpoint reports busy, the store notes that superseded frames
//! may remain, and the next flush and the next erase try again. A busy
//! checkpoint never fails the operation that asked for it: that operation's
//! state is already committed.
//!
//! What this does not reach is below SQLite: blocks the filesystem freed when
//! the log was truncated, and flash the controller remapped, are outside what
//! a library can erase (docs/mls-core.md §Security considerations).
//!
//! ## Another process on the file
//!
//! Two processes may hold the same file at once: the app and its
//! notification extension. Each keeps its groups in memory between
//! operations, and OpenMLS writes a group's state back whole, so a process
//! that acted on the copy it loaded before the other one wrote would put
//! the older copy back: a message key the other process spent, or an epoch
//! the group has left (docs/mls-core.md §A store two processes
//! share).
//!
//! So an operation that writes group state starts with
//! [`KvStore::begin_write`], an `IMMEDIATE` transaction that takes the
//! write lock before the operation reads anything, and asks
//! [`KvStore::foreign_generation`], SQLite's `data_version`, which moves
//! only when another connection has committed. When it moved since the
//! client last loaded its groups, the client loads them again, inside the
//! same transaction, and only then acts. The check, the work and the write
//! are one transaction, and no other connection can commit between them.
//!
//! ## Encryption at rest
//!
//! The C library underneath is SQLCipher, not plain SQLite (`Cargo.toml`
//! names the features). [`SqliteKv::open_encrypted`] keys the connection with
//! a 32-byte RAW key before it reads a page, so every page on disk — the
//! file, its WAL and its journal — is AES-256 ciphertext and the file does not
//! even begin with SQLite's magic header. The shape: a random key, wrapped
//! by the platform keystore, and handed to SQLCipher for each database. The
//! key is RAW rather
//! than a passphrase (`x'…'`), so SQLCipher runs no PBKDF2: the key is already
//! 256 random bits and a KDF would only slow every open.
//!
//! Where the key lives is the caller's business, as the path is. A server
//! daemon keeps it apart from the store: a credential its service manager
//! hands it (systemd credentials), a key service, or a TPM, never a file
//! beside the store. [`SqliteKv::open_encrypted`] refuses a wrong key and a
//! file from before encryption alike, rather than repairing either.
//! [`SqliteKv::open_store`] tells them apart: a store in the clear is
//! [`crate::Error::PlaintextStore`], which no retry fixes and which
//! [`store_encrypt_in_place`] migrates; a store that does not open under the
//! key stays [`crate::Error::Storage`]. Its `must_exist` refuses a path with
//! no store rather than starting an empty one, which would drop the device
//! out of every group.
//!
//! [`SqliteKv::open`] still opens a file with no key, as ordinary SQLite, but
//! only in a build with the `insecure-plaintext-store` feature: tests and
//! tools. A store in the clear holds every group secret for any reader of the
//! disk.
//!
//! ## Encrypting a store in place
//!
//! [`store_encrypt_in_place`] turns a store written in the clear into one
//! under a key, leaving no moment with no store and no plaintext copy: it
//! folds the log into the file, exports every row into a new file under the
//! key beside it, checks that file opens and holds the same rows, syncs it,
//! removes the old log and index, renames the new file over the old one and
//! syncs the directory. A crash before the rename leaves the store in the
//! clear and a partial file the next attempt removes; after it, the
//! encrypted store, with the old file's permissions. The old file's blocks
//! are freed, not overwritten, so until the filesystem reuses them they hold
//! the store in the clear (docs/mls-core.md §Security considerations).
//! Nothing else may hold the store open meanwhile.
//!
//! ## Only this process's user writes the files
//!
//! The SQLite underneath (before 3.54, RUSTSEC-2026-0459, and no SQLCipher
//! build bundles the fix yet) trusts a `-wal` file it finds beside the
//! store: a crafted one can make it hand back stale memory. So every open,
//! and [`store_encrypt_in_place`], first refuses a store whose file, `-wal`,
//! `-shm` or `-journal` is writable by group or others
//! ([`check_store_permissions`], [`crate::Error::InsecureStore`]), with
//! nothing opened or created. A file that is not there is fine: SQLite
//! creates the store `0644` and each of the others with the store's own
//! mode, so none is group- or other-writable unless something changed it.
//! The directory is the caller's: one others can write lets them add a
//! `-wal` after the check, so it belongs in storage only this client can
//! write too. Not judged off Unix.
//!
//! ## The plaintext header
//!
//! [`SqliteKv::open_encrypted_with_plaintext_header`] is the same encryption
//! with the first 32 bytes of the file left as SQLite's own header, and the
//! salt SQLCipher would have kept there passed in beside the key (a 48-byte
//! keyspec). It exists for iOS, which kills a suspended app holding a lock on
//! a shared-container file it cannot recognise as a WAL database by its
//! header. Those 32 bytes are the
//! magic string, the page size and a few counters; every page's content,
//! including the rest of page 1, is still ciphertext.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use crate::storage::{KvEntry, KvError, KvStore};

/// A key-value store in a SQLite file.
///
/// The `Mutex` is what makes this `Sync`. `rusqlite::Connection` is `Send` and
/// not `Sync` — SQLite's own thread-safety is a compile-time option of the
/// library, not a property of a connection handle — and the KV trait is `&self`
/// throughout, so the lock is the honest way to satisfy it. Contention is not a
/// concern the lock introduces: the C ABI already says one client is not
/// thread-safe and callers serialise (`mls/cabi/src/lib.rs`).
pub struct SqliteKv {
    connection: Mutex<Connection>,
    /// Whether a transaction is open, and whether a write in it failed.
    /// Taken only while the connection's lock is held, so "is there a
    /// transaction" and "write into it" cannot disagree.
    transaction: Mutex<Txn>,
    /// Whether the last truncating checkpoint could not finish, so the log
    /// may still hold superseded frames (module docs, §Erasing what an
    /// operation replaced). The next flush tries again.
    residue_pending: AtomicBool,
}

impl std::fmt::Debug for SqliteKv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No path, no row count. The path names a person's container directory
        // and the count is a rough membership size; neither belongs in whatever
        // a wrapper decides to log.
        f.write_str("SqliteKv")
    }
}

fn sql_err(what: &str, err: rusqlite::Error) -> KvError {
    KvError::new(format!("{what}: {err}"))
}

fn poisoned(what: &str) -> KvError {
    KvError::new(format!("the MLS store's lock is poisoned ({what})"))
}

impl SqliteKv {
    /// Open — or create — the store at `path`.
    ///
    /// The file and its journal are the device's group state in the clear. The
    /// caller is responsible for putting it somewhere the platform protects and
    /// does not back up: `noBackupFilesDir` on Android, a backup-excluded
    /// container file on Apple (docs/mls-core.md §Storage layout). This
    /// function deliberately does not pick a directory — a library that chose
    /// one would be choosing it for four apps.
    #[cfg(feature = "insecure-plaintext-store")]
    pub fn open(path: impl AsRef<Path>) -> Result<Self, KvError> {
        Self::prepare(Self::connect(path.as_ref())?)
    }

    /// Open the store at `path` under `key`: 32 bytes is
    /// [`SqliteKv::open_encrypted`], 48 is
    /// [`SqliteKv::open_encrypted_with_plaintext_header`]. A store written in
    /// the clear is [`crate::Error::PlaintextStore`], never touched; with
    /// `must_exist`, a path with no store is
    /// [`crate::Error::InvalidArgument`] and nothing is created. A store
    /// whose files group or others can write is
    /// [`crate::Error::InsecureStore`] (module docs, §Only this process's
    /// user writes the files). Every other failure is
    /// [`crate::Error::Storage`].
    pub fn open_store(path: impl AsRef<Path>, key: &[u8], must_exist: bool) -> crate::Result<Self> {
        let path = path.as_ref();
        let plaintext_header = keyspec_layout(key)?;
        check_store_permissions(path)?;
        if !path.exists() {
            if must_exist {
                return Err(crate::Error::invalid(
                    "there is no MLS store at this path, and the open asked for an existing one",
                ));
            }
        } else if Self::is_plaintext_store(path) {
            return Err(crate::Error::PlaintextStore);
        }
        Ok(Self::open_keyed(path, &key_pragma(key), plaintext_header)?)
    }

    /// Whether `path` holds a store written in the clear, judged from the
    /// first 100 bytes alone, the database header SQLite writes in the clear
    /// (<https://www.sqlite.org/fileformat2.html#the_database_header>): its
    /// magic string, a schema format of 1 to 4 at offset 44, and the twenty
    /// bytes at 72 that SQLite reserves and keeps zero. A file under a key is
    /// ciphertext there: from byte 0 in the ordinary layout, and from byte 32
    /// in the plaintext-header one, whose first 32 bytes match a plain file's.
    /// Nothing opens the file as a database, so a probe makes no log or index
    /// beside a store. False for a path with no file, or a shorter one.
    pub fn is_plaintext_store(path: impl AsRef<Path>) -> bool {
        let mut header = [0u8; 100];
        let read = std::fs::File::open(path.as_ref())
            .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut header));
        if read.is_err() || &header[..16] != b"SQLite format 3\0" {
            return false;
        }
        let schema_format = u32::from_be_bytes([header[44], header[45], header[46], header[47]]);
        (1..=4).contains(&schema_format) && header[72..92].iter().all(|byte| *byte == 0)
    }

    /// Open — or create — the store at `path`, encrypted with SQLCipher under
    /// a 32-byte raw `key` (module docs, §Encryption at rest).
    ///
    /// Refuses, with an error and without touching the file, a file this key
    /// does not open: one written under another key, and one written with no
    /// key at all. Deleting it is the caller's decision.
    pub fn open_encrypted(path: impl AsRef<Path>, key: &[u8; 32]) -> Result<Self, KvError> {
        Self::open_keyed(path.as_ref(), &key_pragma(key), false)
    }

    /// [`SqliteKv::open_encrypted`] with a 48-byte `keyspec` — a 32-byte raw
    /// key followed by a 16-byte salt — and the first 32 bytes of the file
    /// left as SQLite's own plaintext header (module docs, §The plaintext
    /// header).
    ///
    /// The Apple clients' door and nobody else's. iOS terminates a suspended
    /// app (0xdead10cc) that holds a lock on a file in a shared container
    /// unless it recognises that file, by its header, as a SQLite database in
    /// WAL mode; the store lives in the app group so the notification service
    /// extension can open it. A plaintext header means the salt SQLCipher
    /// would otherwise keep in those bytes has to come from the caller, which
    /// is what the last sixteen bytes of `keyspec` are.
    pub fn open_encrypted_with_plaintext_header(
        path: impl AsRef<Path>,
        keyspec: &[u8; 48],
    ) -> Result<Self, KvError> {
        Self::open_keyed(path.as_ref(), &key_pragma(keyspec), true)
    }

    fn open_keyed(path: &Path, key_pragma: &str, plaintext_header: bool) -> Result<Self, KvError> {
        let connection = Self::connect(path)?;
        // The key before anything reads a page — SQLCipher applies it to the
        // first page read, and `journal_mode` below is one.
        connection
            .execute_batch(key_pragma)
            .map_err(|err| sql_err("could not key the MLS store", err))?;
        // Also before the first read: it changes how page 1 is laid out. Set
        // both ways rather than left to SQLCipher's process-wide default, which
        // another database in the same process may have changed.
        let header = if plaintext_header { 32 } else { 0 };
        connection
            .execute_batch(&format!("PRAGMA cipher_plaintext_header_size = {header};"))
            .map_err(|err| sql_err("could not set the plaintext header", err))?;
        // A plain-SQLite build would accept `PRAGMA key` as an unknown pragma
        // and carry on writing cleartext. `cipher_version` answers only under
        // SQLCipher, so this is the check that the file really is encrypted.
        let cipher: Option<String> = connection
            .query_row("PRAGMA cipher_version;", [], |row| row.get(0))
            .ok();
        if cipher.is_none_or(|v| v.is_empty()) {
            return Err(KvError::new(
                "the MLS store was built without SQLCipher and cannot encrypt".to_string(),
            ));
        }
        // The first read of a page: this is where a wrong key, or a file from
        // before encryption, says "file is not a database".
        connection
            .query_row("SELECT count(*) FROM sqlite_master;", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|err| sql_err("the MLS store does not open under this key", err))?;
        Self::prepare(connection)
    }

    fn connect(path: &Path) -> Result<Connection, KvError> {
        // Every file open, whichever door: the typed refusal is
        // `open_store`'s, which asks first; here it is a storage error.
        check_store_permissions(path).map_err(|err| KvError::new(err.to_string()))?;
        Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                // No URI parsing: a group id never reaches this path, but a
                // container directory with a `?` in it would otherwise become a
                // query string.
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|err| sql_err("could not open the MLS store", err))
    }

    /// A store in memory, with SQLite doing the work.
    ///
    /// For the tests that want the SQLite code path — the statement text, the
    /// BLOB round trip, the prefix range — without a file to clean up. NOT the
    /// ephemeral path a caller should reach for: that is
    /// [`MemoryKv`](crate::storage::MemoryKv), which has no C library under it.
    pub fn in_memory() -> Result<Self, KvError> {
        let connection = Connection::open_in_memory()
            .map_err(|err| sql_err("could not open an in-memory MLS store", err))?;
        Self::prepare(connection)
    }

    fn prepare(connection: Connection) -> Result<Self, KvError> {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|err| sql_err("could not set the journal mode", err))?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|err| sql_err("could not set the synchronous mode", err))?;
        // Module docs, §Durability: an acknowledged envelope's operation must
        // survive a power cut, so a checkpoint flushes to the medium too.
        connection
            .pragma_update(None, "checkpoint_fullfsync", "ON")
            .map_err(|err| sql_err("could not set the checkpoint flush", err))?;
        // Module docs, §Erasing what an operation replaced. Both are
        // per-connection settings, so they are set on every open.
        connection
            .pragma_update(None, "secure_delete", "ON")
            .map_err(|err| sql_err("could not turn on secure delete", err))?;
        connection
            .pragma_update(None, "journal_size_limit", 0)
            .map_err(|err| sql_err("could not set the journal size limit", err))?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS mls_kv (k BLOB PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;",
            )
            .map_err(|err| sql_err("could not create the MLS store's table", err))?;
        // Clear whatever log a process killed without closing left behind.
        // Busy (another process holds the file), or any other failure of the
        // checkpoint, is not a failure to open: the flag carries it to the
        // next flush, and a device that cannot open its store has lost more
        // than one that opens it with residue.
        let erased = checkpoint_truncate(&connection).unwrap_or(false);
        Ok(Self {
            connection: Mutex::new(connection),
            transaction: Mutex::new(Txn::default()),
            residue_pending: AtomicBool::new(!erased),
        })
    }

    /// Run a truncating checkpoint now, unless a transaction of this
    /// connection's is open. True when the log is empty afterwards.
    fn erase_now(&self, connection: &Connection) -> Result<bool, KvError> {
        let open = self.transaction.lock().map_err(|_| poisoned("erase"))?.open;
        // An open transaction holds writes the core has not flushed yet (no
        // call returns with one open, but an erase may be asked for inside
        // an operation), and a checkpoint inside one is refused anyway.
        // Erasing never commits on the caller's behalf.
        let erased = !open && checkpoint_truncate(connection)?;
        self.residue_pending.store(!erased, Ordering::Release);
        Ok(erased)
    }

    /// Open a deferred transaction if one is not already open.
    ///
    /// Deferred and not immediate: the write lock is taken at the first write
    /// statement rather than here, so a store that is opened and only read
    /// never blocks another connection.
    fn begin_if_needed(&self, connection: &Connection, txn: &mut Txn) -> Result<(), KvError> {
        if !txn.open {
            connection
                .execute_batch("BEGIN DEFERRED;")
                .map_err(|err| sql_err("could not begin a store transaction", err))?;
            txn.open = true;
        }
        Ok(())
    }

    /// Open an IMMEDIATE transaction if none is open: the write lock now,
    /// rather than at the first write (module docs, §Another process on the
    /// file). A transaction already open holds it: this connection opens one
    /// only at a write, and the write took the lock.
    fn begin_immediate_if_needed(&self, connection: &Connection) -> Result<(), KvError> {
        let mut txn = self.transaction.lock().map_err(|_| poisoned("begin"))?;
        if !txn.open {
            connection
                .execute_batch("BEGIN IMMEDIATE;")
                .map_err(|err| sql_err("could not take the MLS store's write lock", err))?;
            txn.open = true;
        }
        Ok(())
    }

    /// One write statement inside the open transaction (module docs,
    /// §Durability, and why `flush` is a commit). A write after one that
    /// failed is refused without running: on some failures SQLite has already
    /// rolled the whole transaction back, and a statement run then would be
    /// committed on its own.
    fn write(
        &self,
        what: &str,
        run: impl FnOnce(&Connection) -> rusqlite::Result<usize>,
    ) -> Result<(), KvError> {
        let connection = self.connection.lock().map_err(|_| poisoned(what))?;
        let mut txn = self.transaction.lock().map_err(|_| poisoned(what))?;
        if txn.failed {
            return Err(KvError::new(
                "an earlier write in this store transaction failed; it will be rolled back",
            ));
        }
        let outcome = self
            .begin_if_needed(&connection, &mut txn)
            .and_then(|()| run(&connection).map(drop).map_err(|err| sql_err(what, err)));
        if outcome.is_err() {
            txn.failed = true;
            // SQLite rolls the whole transaction back itself on some
            // failures (a full disk, an I/O error); the flag above is then
            // all that stands between the next write and autocommit.
            if connection.is_autocommit() {
                txn.open = false;
            }
        }
        outcome
    }

    /// Close the open transaction: COMMIT it, or, when a write in it failed,
    /// ROLL IT BACK and say so. Never commits a transaction that lost a
    /// write, whichever path closes it: the core's flush, the C ABI's commit
    /// after a call, or `Drop`.
    fn commit_if_open(&self, connection: &Connection) -> Result<(), KvError> {
        let mut txn = self.transaction.lock().map_err(|_| poisoned("commit"))?;
        if txn.failed {
            Self::roll_back(connection, &mut txn);
            self.residue_pending.store(true, Ordering::Release);
            return Err(KvError::new(
                "a write in this store transaction failed, so it was rolled back, not committed",
            ));
        }
        if txn.open {
            connection
                .execute_batch("COMMIT;")
                .map_err(|err| sql_err("could not commit to the MLS store", err))?;
            txn.open = false;
        }
        Ok(())
    }

    /// ROLLBACK whatever is open and clear both flags. A ROLLBACK that finds
    /// no transaction (SQLite already rolled it back) is what was wanted.
    fn roll_back(connection: &Connection, txn: &mut Txn) {
        if txn.open && !connection.is_autocommit() {
            let _ = connection.execute_batch("ROLLBACK;");
        }
        *txn = Txn::default();
    }
}

/// [`SqliteKv`]'s view of its own transaction.
#[derive(Debug, Default)]
struct Txn {
    /// A transaction is open on the connection.
    open: bool,
    /// A write in it failed: it is rolled back, never committed.
    failed: bool,
}

impl Drop for SqliteKv {
    fn drop(&mut self) {
        // Best effort, and it has to be: `Drop` cannot fail and cannot report.
        // A client that flushed after its last operation has nothing open here.
        // A transaction that lost a write is rolled back, not committed.
        if let Ok(connection) = self.connection.lock() {
            let _ = self.commit_if_open(&connection);
        }
    }
}

impl KvStore for SqliteKv {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        let connection = self.connection.lock().map_err(|_| poisoned("get"))?;
        let mut statement = connection
            .prepare_cached("SELECT v FROM mls_kv WHERE k = ?1")
            .map_err(|err| sql_err("could not prepare a store read", err))?;
        let mut rows = statement
            .query([key])
            .map_err(|err| sql_err("could not read from the MLS store", err))?;
        match rows
            .next()
            .map_err(|err| sql_err("could not read from the MLS store", err))?
        {
            Some(row) => {
                Ok(Some(row.get(0).map_err(|err| {
                    sql_err("could not read a stored value", err)
                })?))
            }
            None => Ok(None),
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        self.write("could not write to the MLS store", |connection| {
            connection
                .prepare_cached("INSERT INTO mls_kv (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v")?
                .execute((key, value))
        })
    }

    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        self.write("could not delete from the MLS store", |connection| {
            connection
                .prepare_cached("DELETE FROM mls_kv WHERE k = ?1")?
                .execute([key])
        })
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<KvEntry>, KvError> {
        let connection = self.connection.lock().map_err(|_| poisoned("scan"))?;
        // A range over the primary key, not `LIKE` and not a blob function:
        // `LIKE` on a BLOB does not do what it does on text, `substr` would
        // read every row, and a range is an index seek. The upper bound is the
        // prefix with its last byte incremented — the standard trick — and an
        // all-0xFF prefix has no successor, which is why the open-ended query
        // is a separate statement rather than a clever one.
        let rows = match successor(prefix) {
            Some(upper) => {
                let mut statement = connection
                    .prepare_cached("SELECT k, v FROM mls_kv WHERE k >= ?1 AND k < ?2 ORDER BY k")
                    .map_err(|err| sql_err("could not prepare a store scan", err))?;
                let mapped = statement
                    .query_map((prefix, upper.as_slice()), |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(|err| sql_err("could not scan the MLS store", err))?
                    .collect::<Result<Vec<_>, _>>();
                mapped
            }
            None => {
                let mut statement = connection
                    .prepare_cached("SELECT k, v FROM mls_kv WHERE k >= ?1 ORDER BY k")
                    .map_err(|err| sql_err("could not prepare a store scan", err))?;
                let mapped = statement
                    .query_map([prefix], |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(|err| sql_err("could not scan the MLS store", err))?
                    .collect::<Result<Vec<_>, _>>();
                mapped
            }
        };
        rows.map_err(|err| sql_err("could not read a scanned row", err))
    }

    fn flush(&self) -> Result<(), KvError> {
        let connection = self.connection.lock().map_err(|_| poisoned("flush"))?;
        self.commit_if_open(&connection)?;
        // The retry for a checkpoint that found the file busy. Its outcome is
        // not this flush's: the commit above is what the caller asked for.
        if self.residue_pending.load(Ordering::Acquire) {
            let _ = self.erase_now(&connection);
        }
        Ok(())
    }

    /// Module docs, §Durability, and why `flush` is a commit. Releases the
    /// write lock. The log is then truncated at the next flush: a rolled-back
    /// transaction may have spilled pages into it.
    fn rollback(&self) -> Result<(), KvError> {
        let connection = self.connection.lock().map_err(|_| poisoned("rollback"))?;
        let mut txn = self.transaction.lock().map_err(|_| poisoned("rollback"))?;
        Self::roll_back(&connection, &mut txn);
        self.residue_pending.store(true, Ordering::Release);
        Ok(())
    }

    /// Module docs, §Erasing what an operation replaced.
    fn erase_superseded(&self) -> Result<bool, KvError> {
        let connection = self.connection.lock().map_err(|_| poisoned("erase"))?;
        self.erase_now(&connection)
    }

    /// Module docs, §Another process on the file. Waits for another
    /// connection's write lock as long as the connection's busy timeout,
    /// as a first write would.
    fn begin_write(&self) -> Result<(), KvError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| poisoned("begin write"))?;
        self.begin_immediate_if_needed(&connection)
    }

    /// [`Self::begin_write`] with no wait: the busy timeout is zero for the
    /// `BEGIN IMMEDIATE` alone and restored after it, as for the checkpoint.
    /// False, with nothing taken, when another connection holds the lock.
    fn try_begin_write(&self) -> Result<bool, KvError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| poisoned("try begin write"))?;
        let mut txn = self.transaction.lock().map_err(|_| poisoned("try begin"))?;
        if txn.open {
            return Ok(true);
        }
        let waited: i64 = connection
            .query_row("PRAGMA busy_timeout;", [], |row| row.get(0))
            .map_err(|err| sql_err("could not read the busy timeout", err))?;
        connection
            .busy_timeout(Duration::ZERO)
            .map_err(|err| sql_err("could not set the busy timeout", err))?;
        let outcome = connection.execute_batch("BEGIN IMMEDIATE;");
        let restored =
            connection.busy_timeout(Duration::from_millis(u64::try_from(waited).unwrap_or(0)));
        let taken = match outcome {
            Ok(()) => {
                txn.open = true;
                true
            }
            Err(err)
                if matches!(
                    err.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                ) =>
            {
                false
            }
            Err(err) => return Err(sql_err("could not take the MLS store's write lock", err)),
        };
        restored.map_err(|err| sql_err("could not restore the busy timeout", err))?;
        Ok(taken)
    }

    /// `PRAGMA data_version`: SQLite changes it for this connection exactly
    /// when another connection, in this process or another, has committed to
    /// the file, and never for this connection's own commits.
    fn foreign_generation(&self) -> Result<Option<u64>, KvError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| poisoned("data version"))?;
        let version: i64 = connection
            .query_row("PRAGMA data_version;", [], |row| row.get(0))
            .map_err(|err| sql_err("could not read the store's data version", err))?;
        Ok(Some(u64::from_ne_bytes(version.to_ne_bytes())))
    }
}

/// `PRAGMA wal_checkpoint(TRUNCATE)`, without waiting on another connection.
///
/// True when the log is empty afterwards (or the database has none, as an
/// in-memory one does not). False when another connection held a lock the
/// checkpoint needed: SQLite reports that as a `busy` column of 1 rather than
/// an error.
///
/// The busy timeout is zero for the checkpoint alone and restored after it.
/// With the connection's ordinary timeout, a reader in another process would
/// stall this one's send or receive for seconds; a skipped checkpoint costs
/// only a retry at the next flush.
fn checkpoint_truncate(connection: &Connection) -> Result<bool, KvError> {
    let waited: i64 = connection
        .query_row("PRAGMA busy_timeout;", [], |row| row.get(0))
        .map_err(|err| sql_err("could not read the busy timeout", err))?;
    connection
        .busy_timeout(Duration::ZERO)
        .map_err(|err| sql_err("could not set the busy timeout", err))?;
    let outcome = connection.query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
    });
    let restored =
        connection.busy_timeout(Duration::from_millis(u64::try_from(waited).unwrap_or(0)));
    let (busy, frames_left) =
        outcome.map_err(|err| sql_err("could not checkpoint the MLS store", err))?;
    restored.map_err(|err| sql_err("could not restore the busy timeout", err))?;
    // `frames_left` is the log's length in frames after the checkpoint, and
    // -1 for a database not in WAL mode.
    Ok(busy == 0 && frames_left <= 0)
}

/// The statement that keys a connection with the raw `key`, in upper-case
/// hex, the spelling SQLCipher's raw-key literal takes. Built in one buffer
/// sized up front, so no reallocation leaves a copy of the key behind, and
/// wiped when dropped. SQLCipher's own copy of the key is SQLCipher's.
fn key_pragma(key: &[u8]) -> zeroize::Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    const HEAD: &str = "PRAGMA key = \"x'";
    const TAIL: &str = "'\";";
    let mut out = zeroize::Zeroizing::new(String::with_capacity(
        HEAD.len() + 2 * key.len() + TAIL.len(),
    ));
    out.push_str(HEAD);
    for byte in key {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    out.push_str(TAIL);
    out
}

/// Whether a store key is a raw key (32 bytes, false) or a raw key and a
/// salt for the plaintext-header layout (48 bytes, true).
fn keyspec_layout(key: &[u8]) -> crate::Result<bool> {
    match key.len() {
        32 => Ok(false),
        48 => Ok(true),
        other => Err(crate::Error::invalid(format!(
            "a store key is 32 or 48 bytes, got {other}"
        ))),
    }
}

/// `path` with `suffix` appended to its file name.
fn with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    std::path::PathBuf::from(name)
}

/// The files SQLite keeps for a store at `path`: the store, its log, its
/// shared-memory index and its rollback journal.
#[cfg(unix)]
const STORE_FILES: [&str; 4] = ["", "-wal", "-shm", "-journal"];

/// THE STORE'S FILES ARE WRITABLE ONLY BY THEIR OWNER (module docs, §Only
/// this process's user writes the files): [`crate::Error::InsecureStore`],
/// naming the file and its mode, when the store at `path` or its `-wal`,
/// `-shm` or `-journal` grants write to group or others, or is a symbolic
/// link. A file that is not there passes, and so does every file off Unix.
/// Reads metadata only; nothing is opened or created. The owner is not
/// judged: a file another user owns passes on its mode, which is why the
/// directory must be writable by this user alone.
pub fn check_store_permissions(path: impl AsRef<Path>) -> crate::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = path.as_ref();
        for suffix in STORE_FILES {
            let file = with_suffix(path, suffix);
            // The link itself, never what it points at: a symbolic link
            // passes on the mode of a file someone else chose.
            let metadata = match std::fs::symlink_metadata(&file) {
                Ok(metadata) => metadata,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(io_err("could not read the MLS store's permissions", err)),
            };
            let which = if suffix.is_empty() { "file" } else { suffix };
            if metadata.file_type().is_symlink() {
                return Err(crate::Error::InsecureStore(format!(
                    "the MLS store's {which} is a symbolic link: keep the store's files in a \
                     directory only this user can write, and open it again"
                )));
            }
            let mode = metadata.permissions().mode();
            if mode & 0o022 != 0 {
                return Err(crate::Error::InsecureStore(format!(
                    "the MLS store's {which} is writable by group or others (mode {:04o}): \
                     make it writable only by its owner (chmod go-w) and open it again",
                    mode & 0o7777
                )));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Remove `path`'s log and shared-memory index, if there are any.
fn remove_sidecars(path: &Path) -> std::io::Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        match std::fs::remove_file(with_suffix(path, suffix)) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn io_err(what: &str, err: std::io::Error) -> crate::Error {
    crate::Error::Storage(format!("{what}: {err}"))
}

/// ENCRYPT A STORE IN PLACE (module docs, §Encrypting a store in place): the
/// store at `path`, written in the clear, becomes one under `key` (32 bytes,
/// or 48 for the plaintext-header layout), with every row kept and no
/// plaintext copy left. Refused, with nothing changed, for a path with no
/// store ([`crate::Error::InvalidArgument`]) and for a store that is not in
/// the clear ([`crate::Error::InvalidArgument`]: open it with its key). A
/// failure part-way leaves the store in the clear, as it was; run it again.
/// Nothing else may hold the store open.
pub fn store_encrypt_in_place(path: impl AsRef<Path>, key: &[u8]) -> crate::Result<()> {
    let path = path.as_ref();
    let plaintext_header = keyspec_layout(key)?;
    if !path.exists() {
        return Err(crate::Error::invalid("there is no MLS store at this path"));
    }
    if !SqliteKv::is_plaintext_store(path) {
        return Err(crate::Error::invalid(
            "the MLS store at this path is not in the clear: open it with its key",
        ));
    }
    check_store_permissions(path)?;
    let temporary = with_suffix(path, ".encrypting");
    let _ = std::fs::remove_file(&temporary);
    remove_sidecars(&temporary).map_err(|err| io_err("could not clear an earlier attempt", err))?;

    let rows = {
        let connection = Connection::open_with_flags(
            path,
            // CREATE is for the attached file, which takes the main file's
            // flags; the store itself was checked to be there.
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|err| crate::Error::from(sql_err("could not open the store in the clear", err)))?;
        // The whole store in the main file, so the export reads every row and
        // no log is left to delete with rows in it.
        if !checkpoint_truncate(&connection)? {
            return Err(crate::Error::Storage(
                "the store's log could not be folded in: another connection holds it".into(),
            ));
        }
        let temporary_name = temporary
            .to_str()
            .ok_or_else(|| crate::Error::invalid("the store path is not UTF-8"))?;
        let mut key_literal = zeroize::Zeroizing::new(String::with_capacity(4 + 2 * key.len()));
        key_literal.push_str("x'");
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for byte in key {
            key_literal.push(char::from(HEX[usize::from(byte >> 4)]));
            key_literal.push(char::from(HEX[usize::from(byte & 0x0F)]));
        }
        key_literal.push('\'');
        connection
            .execute(
                "ATTACH DATABASE ?1 AS encrypted KEY ?2",
                rusqlite::params![temporary_name, key_literal.as_str()],
            )
            .map_err(|err| {
                crate::Error::from(sql_err("could not create the encrypted store", err))
            })?;
        let header = if plaintext_header { 32 } else { 0 };
        connection
            .execute_batch(&format!(
                "PRAGMA encrypted.cipher_plaintext_header_size = {header};"
            ))
            .map_err(|err| {
                crate::Error::from(sql_err("could not set the plaintext header", err))
            })?;
        connection
            .query_row("SELECT sqlcipher_export('encrypted');", [], |_| Ok(()))
            .map_err(|err| crate::Error::from(sql_err("could not export the store", err)))?;
        let rows: i64 = connection
            .query_row("SELECT count(*) FROM main.mls_kv;", [], |row| row.get(0))
            .map_err(|err| crate::Error::from(sql_err("could not count the store's rows", err)))?;
        connection
            .execute_batch("DETACH DATABASE encrypted;")
            .map_err(|err| {
                crate::Error::from(sql_err("could not close the encrypted store", err))
            })?;
        rows
    };

    // The new file opens under the key and holds every row, before anything
    // of the old one goes.
    {
        let encrypted = SqliteKv::open_keyed(&temporary, &key_pragma(key), plaintext_header)?;
        let connection = encrypted
            .connection
            .lock()
            .map_err(|_| crate::Error::from(poisoned("encrypt in place")))?;
        let copied: i64 = connection
            .query_row("SELECT count(*) FROM mls_kv;", [], |row| row.get(0))
            .map_err(|err| {
                crate::Error::from(sql_err("could not read the encrypted store", err))
            })?;
        if copied != rows {
            return Err(crate::Error::Storage(format!(
                "the encrypted store holds {copied} rows of {rows}: left in the clear"
            )));
        }
    }
    remove_sidecars(&temporary)
        .map_err(|err| io_err("could not clear the new store's log", err))?;
    // The new file takes the old one's permissions, not SQLite's default:
    // a store its owner kept private stays private. That is the whole mode,
    // any setuid, setgid or sticky bit its owner set included; a mode group
    // or others can write was refused above.
    let permissions = std::fs::metadata(path)
        .map_err(|err| io_err("could not read the store's permissions", err))?
        .permissions();
    std::fs::set_permissions(&temporary, permissions)
        .map_err(|err| io_err("could not set the encrypted store's permissions", err))?;
    std::fs::File::open(&temporary)
        .and_then(|file| file.sync_all())
        .map_err(|err| io_err("could not sync the encrypted store", err))?;
    remove_sidecars(path).map_err(|err| io_err("could not remove the old store's log", err))?;
    std::fs::rename(&temporary, path)
        .map_err(|err| io_err("could not put the encrypted store in place", err))?;
    if let Some(directory) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        // The rename's own durability. A platform that cannot open a
        // directory to sync it has already put the file in place.
        if let Ok(directory) = std::fs::File::open(directory) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

/// The smallest byte string greater than every string starting with `prefix`,
/// or `None` when there is none (an empty prefix, or one that is all 0xFF).
fn successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut upper = prefix.to_vec();
    while let Some(last) = upper.pop() {
        if last != 0xff {
            upper.push(last + 1);
            return Some(upper);
        }
    }
    None
}

#[cfg(test)]
// As `fixture.rs`: the crate denies `expect` for the LIBRARY, and a test that
// cannot proceed should stop on the line that failed.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::storage::{namespace_prefix, storage_key};

    #[test]
    fn a_value_round_trips_as_bytes() {
        let kv = SqliteKv::in_memory().expect("open");
        let key = storage_key(b"tree", b"[1,2]");
        assert_eq!(kv.get(&key).expect("get"), None);
        kv.put(&key, &[0, 159, 146, 150]).expect("put");
        kv.flush().expect("flush");
        assert_eq!(
            kv.get(&key).expect("get"),
            Some(vec![0, 159, 146, 150]),
            "a value with a NUL and invalid UTF-8 must survive"
        );
        kv.delete(&key).expect("delete");
        assert_eq!(kv.get(&key).expect("get"), None);
        // Deleting what is not there is success.
        kv.delete(&key).expect("second delete");
    }

    #[test]
    fn a_scan_is_bounded_by_the_prefix() {
        let kv = SqliteKv::in_memory().expect("open");
        kv.put(&storage_key(b"ab", b"one"), b"1").expect("put");
        kv.put(&storage_key(b"ab", b"two"), b"2").expect("put");
        kv.put(&storage_key(b"abc", b"three"), b"3").expect("put");
        kv.put(&storage_key(b"zz", b"four"), b"4").expect("put");
        let found = kv.scan(&namespace_prefix(b"ab")).expect("scan");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].1, b"1".to_vec(), "a scan is in key order");
    }

    #[test]
    fn the_successor_of_an_all_ff_prefix_is_open_ended() {
        assert_eq!(successor(b"ab"), Some(b"ac".to_vec()));
        assert_eq!(successor(&[0x01, 0xff]), Some(vec![0x02]));
        assert_eq!(successor(&[0xff, 0xff]), None);
        assert_eq!(successor(b""), None);
        let kv = SqliteKv::in_memory().expect("open");
        kv.put(&[0xff, 0xff, 0x01], b"x").expect("put");
        assert_eq!(kv.scan(&[0xff, 0xff]).expect("scan").len(), 1);
    }

    /// Module docs, §Durability: a commit syncs the log (`FULL` = 2), and a
    /// checkpoint uses the full flush, on every file store.
    #[test]
    fn a_file_store_syncs_each_commit_and_each_checkpoint() {
        let dir = std::env::temp_dir().join(format!("peachy-mls-kv-sync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let path = dir.join("sync.sqlite3");
        let _ = std::fs::remove_file(&path);
        let kv = SqliteKv::open(&path).expect("open");
        let connection = kv.connection.lock().expect("lock");
        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous;", [], |row| row.get(0))
            .expect("synchronous");
        let fullfsync: i64 = connection
            .query_row("PRAGMA checkpoint_fullfsync;", [], |row| row.get(0))
            .expect("checkpoint_fullfsync");
        assert_eq!(synchronous, 2, "each commit must sync the log (FULL)");
        assert_eq!(fullfsync, 1, "a checkpoint must flush to the medium");
        drop(connection);
        drop(kv);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The buffered-write contract: nothing an unflushed connection wrote is
    /// visible to a second one, and everything a flushed one wrote is.
    #[test]
    fn a_flush_is_what_makes_a_write_visible_to_another_connection() {
        let dir = std::env::temp_dir().join(format!("peachy-mls-kv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let path = dir.join("flush.sqlite3");
        let _ = std::fs::remove_file(&path);

        let writer = SqliteKv::open(&path).expect("open writer");
        writer.put(b"k", b"v").expect("put");
        {
            let reader = SqliteKv::open(&path).expect("open reader");
            assert_eq!(
                reader.get(b"k").expect("get"),
                None,
                "an uncommitted write must not be visible"
            );
        }
        writer.flush().expect("flush");
        {
            let reader = SqliteKv::open(&path).expect("open reader");
            assert_eq!(reader.get(b"k").expect("get"), Some(b"v".to_vec()));
        }
        drop(writer);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A store whose writes of the key `bad` fail: `RAISE(ABORT)` undoes
    /// the statement and leaves the transaction open (what most errors do),
    /// `RAISE(ROLLBACK)` undoes the whole transaction (what SQLite does on a
    /// full disk or an I/O error).
    fn failing_store(name: &str, raise: &str) -> (SqliteKv, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("peachy-mls-kv-fail-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tempdir");
        let path = dir.join("fail.sqlite3");
        let kv = SqliteKv::open(&path).expect("open");
        kv.connection
            .lock()
            .expect("lock")
            .execute_batch(&format!(
                "CREATE TRIGGER fail_bad BEFORE INSERT ON mls_kv WHEN NEW.k = CAST('bad' AS BLOB) \
                 BEGIN SELECT RAISE({raise}, 'injected: disk full'); END;"
            ))
            .expect("trigger");
        (kv, dir)
    }

    /// A transaction that lost a write is never committed: not by a flush,
    /// not by `Drop`, whether SQLite undid the statement or the whole
    /// transaction. The writes after the failure are refused without running,
    /// so none of them autocommits either.
    #[test]
    fn a_transaction_that_lost_a_write_is_rolled_back_not_committed() {
        for raise in ["ABORT", "ROLLBACK"] {
            for close in ["flush", "drop"] {
                let (kv, dir) = failing_store(&format!("{raise}-{close}"), raise);
                let path = dir.join("fail.sqlite3");
                kv.put(b"before", b"1").expect("put before");
                assert!(
                    kv.put(b"bad", b"x").is_err(),
                    "{raise}: the injected failure"
                );
                assert!(
                    kv.put(b"after", b"1").is_err(),
                    "{raise}: a write after a failed one is refused"
                );
                match close {
                    "flush" => assert!(kv.flush().is_err(), "{raise}: the flush says so"),
                    _ => drop(kv),
                }
                let reader = SqliteKv::open(&path).expect("reader");
                assert_eq!(reader.get(b"before").expect("get"), None, "{raise}/{close}");
                assert_eq!(reader.get(b"after").expect("get"), None, "{raise}/{close}");
                drop(reader);
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }

    /// After a rollback the store is usable again, with its write lock
    /// released.
    #[test]
    fn a_rolled_back_store_writes_and_commits_again() {
        let (kv, dir) = failing_store("again", "ABORT");
        let path = dir.join("fail.sqlite3");
        kv.put(b"lost", b"1").expect("put");
        assert!(kv.put(b"bad", b"x").is_err());
        kv.rollback().expect("rollback");
        kv.put(b"kept", b"1").expect("put after the rollback");
        kv.flush().expect("flush");
        let reader = SqliteKv::open(&path).expect("reader");
        assert_eq!(reader.get(b"lost").expect("get"), None);
        assert_eq!(reader.get(b"kept").expect("get"), Some(b"1".to_vec()));
        // The rollback released the lock: another connection can write.
        reader.begin_write().expect("the write lock is free");
        reader.put(b"other", b"1").expect("put");
        reader.flush().expect("flush");
        drop(reader);
        drop(kv);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Encryption at rest: the file an encrypted store writes is not SQLite
    /// to anything without the key — not even its first sixteen bytes, which
    /// in a plain database are the magic string every forensic tool looks
    /// for — and the key opens it again after a close.
    #[test]
    fn an_encrypted_store_is_not_readable_as_sqlite_and_reopens_under_its_key() {
        let dir = std::env::temp_dir().join(format!("peachy-mls-kv-enc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let path = dir.join("encrypted.sqlite");
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        let key = [0x5au8; 32];

        let kv = SqliteKv::open_encrypted(&path, &key).expect("open encrypted");
        kv.put(b"group-secret", b"the words").expect("put");
        kv.flush().expect("flush");
        drop(kv);

        let bytes = std::fs::read(&path).expect("read the file");
        assert!(bytes.len() >= 16, "the store must have written a page");
        assert_ne!(
            &bytes[..16],
            b"SQLite format 3\0",
            "the header must not be SQLite's"
        );
        let needle = b"the words";
        let wal = std::fs::read(format!("{}-wal", path.display())).unwrap_or_default();
        for file in [&bytes, &wal] {
            assert!(
                !file.windows(needle.len()).any(|w| w == needle),
                "a stored value must not appear in the clear"
            );
        }

        // Plain SQLite cannot read it.
        assert!(SqliteKv::open(&path).is_err(), "no key must not open it");
        // Nor can another key.
        assert!(
            SqliteKv::open_encrypted(&path, &[0xa5u8; 32]).is_err(),
            "a wrong key must not open it"
        );
        // Its own key can.
        let again = SqliteKv::open_encrypted(&path, &key).expect("reopen");
        assert_eq!(
            again.get(b"group-secret").expect("get"),
            Some(b"the words".to_vec())
        );
        drop(again);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file from before encryption is refused, not silently read in the
    /// clear: the caller deletes it (docs/mls-core.md §Storage layout).
    #[test]
    fn an_unencrypted_file_does_not_open_under_a_key() {
        let dir = std::env::temp_dir().join(format!("peachy-mls-kv-plain-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let path = dir.join("plain.sqlite");
        let _ = std::fs::remove_file(&path);
        let plain = SqliteKv::open(&path).expect("open plain");
        plain.put(b"k", b"v").expect("put");
        plain.flush().expect("flush");
        drop(plain);
        assert!(SqliteKv::open_encrypted(&path, &[1u8; 32]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The plaintext-header variant (module docs, §The plaintext header): the
    /// first 32 bytes ARE SQLite's header — that is the point — and nothing
    /// after them is readable. A stored value is absent from the file and the
    /// WAL, the file does not open with no key, another key or another salt,
    /// and it reopens under its own keyspec.
    #[test]
    fn a_plaintext_header_store_hides_everything_after_the_header() {
        let dir = std::env::temp_dir().join(format!("peachy-mls-kv-header-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tempdir");
        let path = dir.join("header.sqlite");
        let mut keyspec = [0x3cu8; 48];
        keyspec[32..].copy_from_slice(&[0x77u8; 16]);

        let kv = SqliteKv::open_encrypted_with_plaintext_header(&path, &keyspec).expect("open");
        kv.put(b"group-secret", b"canary-words-in-the-clear")
            .expect("put");
        kv.flush().expect("flush");
        drop(kv);

        let bytes = std::fs::read(&path).expect("read the file");
        assert_eq!(
            &bytes[..16],
            b"SQLite format 3\0",
            "the header must be SQLite's, for iOS"
        );
        let needle = b"canary-words-in-the-clear";
        let wal = std::fs::read(format!("{}-wal", path.display())).unwrap_or_default();
        for file in [&bytes, &wal] {
            assert!(
                !file.windows(needle.len()).any(|w| w == needle),
                "a stored value must not appear in the clear"
            );
            assert!(
                !file.windows(6).any(|w| w == b"mls_kv"),
                "the schema must not appear in the clear"
            );
        }

        assert!(SqliteKv::open(&path).is_err(), "no key must not open it");
        let mut other = keyspec;
        other[0] ^= 1;
        assert!(SqliteKv::open_encrypted_with_plaintext_header(&path, &other).is_err());
        let mut salted = keyspec;
        salted[40] ^= 1;
        assert!(
            SqliteKv::open_encrypted_with_plaintext_header(&path, &salted).is_err(),
            "the salt is part of the key"
        );
        let again =
            SqliteKv::open_encrypted_with_plaintext_header(&path, &keyspec).expect("reopen");
        assert_eq!(
            again.get(b"group-secret").expect("get"),
            Some(b"canary-words-in-the-clear".to_vec())
        );
        drop(again);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
