// SPDX-License-Identifier: MIT
import Foundation
import PeachyMLSCore

/// One signed-in device's MLS state: its credential, its key material, and
/// every group it is in.
///
/// This is the whole Swift surface over `mls/cabi`. Nothing below it escapes:
/// every buffer the C ABI hands back is copied into `Data` and freed before
/// the call returns, and the only raw pointer in the type is the opaque handle
/// this class owns and frees in `deinit`.
///
/// ## Thread safety, and why `@unchecked Sendable` is honest here
///
/// The C ABI is **not** thread-safe, and says so: "one client is one device's
/// MLS state, and two threads committing to the same group at once is a
/// protocol error before it is a data race. Callers serialize."
/// (`mls/cabi/src/lib.rs`, module header.) So this class is the caller that
/// serializes — every entry point takes `lock` for the whole of its C call,
/// including the `peachy_mls_last_error()` read that follows a failure, which
/// matters because that slot is thread-local and is overwritten by the next
/// call on the same thread.
///
/// That makes the type safe to share, which `@unchecked Sendable` asserts and
/// the compiler cannot check. Two facts it rests on, both verified rather than
/// assumed:
///
///  1. the underlying Rust `Client` is `Send` — `mls/core/tests/thread.rs`
///     asserts it at compile time, so moving the state between threads under
///     the lock is sound;
///  2. `Sync` is not required, because the lock means no two threads are ever
///     inside the library on this handle at once.
///
/// What the lock does NOT do is make concurrent use *correct* at the protocol
/// level: two commits to one group from two threads will serialize, and the
/// second will then be a commit against an epoch that has moved. That is the
/// caller's ordering problem, and no lock can answer it.
public final class MLSClient: @unchecked Sendable {
    /// `nil` once ``close()`` has run. Read and written only under `lock`.
    private var openHandle: OpaquePointer?
    private let lock = NSLock()

    /// Build a client from this device's credential and signing seed.
    ///
    /// - Parameters:
    ///   - credential: the `pdc1` token the server issued this device.
    ///   - signatureSeed: exactly 32 bytes, the device's Ed25519 seed from the
    ///     platform key store.
    ///   - trustedKeysJSON: the body of `GET /healthz/device-credential-keys`,
    ///     verbatim. It is passed as JSON rather than parsed here on purpose:
    ///     the core parses it, so key rotation needs no Swift change, and
    ///     there is one implementation of "which server keys do we trust"
    ///     rather than four.
    ///   - storePath: the SQLite file this device's MLS state lives in, or
    ///     `nil` for a client whose groups, key packages and epoch secrets die
    ///     with it. **There is no default.** An app that means to persist and
    ///     an app that means not to should both have to say so, because the
    ///     symptom of getting it wrong — every chat needing a fresh Welcome
    ///     after a relaunch — looks like a server problem from the outside.
    ///     Most callers want `init(…, storeURL:)` below, which also puts the
    ///     file somewhere sensible and keeps it out of backups.
    ///   - storeKey: the key the store is encrypted under with SQLCipher
    ///     (`mls/core/src/sqlite.rs` §Encryption at rest): 32 bytes, or 48 —
    ///     the key and a 16-byte salt — which also keeps the file's first 32
    ///     bytes as SQLite's plaintext header, what the Apple apps pass for a
    ///     store in the app group (§The plaintext header). **Required with a
    ///     `storePath`:** a release build refuses a store path with no key
    ///     (`.invalidArgument`), and only a test build of the library opens a
    ///     file in the clear. `nil` with `storePath` `nil` is an in-memory
    ///     client; a key with no path is refused. A file the key does not
    ///     open — one written under another key, or under none — throws
    ///     `.storage`.
    ///   - ownAccountIdentity: the 32-byte account identity key this device
    ///     derives from the account key it HOLDS
    ///     (``accountIdentityPublicKey(accountKey:)``), or `nil` when it holds none. A
    ///     credential certified under any other account key, or certified at
    ///     all when this is `nil`, throws `.credentialRejected`
    ///     (`notOwnAccountKey`); a credential with no certificate still opens
    ///     (docs/identity.md §The account identity key).
    /// - Throws: `MLSError` with `.credentialRejected` if the credential does
    ///   not check out against those keys — including when the seed is not the
    ///   one the credential names; `.invalidArgument` for a `storePath` with
    ///   no `storeKey` (outside a test build) or a `storeKey` with no
    ///   `storePath`; `.storage` if `storePath` cannot be opened.
    ///   It never falls back to an in-memory store on a bad path: a device that
    ///   silently stopped persisting is worse than one that would not start.
    ///   A key handed with a store written in the clear throws
    ///   `.plaintextStore`: encrypt it with
    ///   ``encryptStoreInPlace(path:key:)`` and open it again, never delete
    ///   it.
    ///   - storeMustExist: open only a store that is already there
    ///     (`peachy_mls_client_open_existing`): a path with no file throws
    ///     `.invalidArgument` and nothing is created, rather than opening an
    ///     empty store that has dropped out of every group. What a process
    ///     reopening its own store passes, so a store lost to a crash or a
    ///     bad migration is an error, not a fresh start.
    public init(
        credential: Data,
        signatureSeed: Data,
        trustedKeysJSON: String,
        storePath: String?,
        storeKey: Data? = nil,
        ownAccountIdentity: Data? = nil,
        storeMustExist: Bool = false
    ) throws {
        #if os(iOS) && DEBUG
            // A store-backed client opened before the app installed its hold
            // is a client whose every call can be frozen mid-read (§Suspension).
            assert(
                storePath == nil || MLSClient.holdsSuspension,
                "MLSClient opened on a store with no suspension hold installed")
        #endif
        // HELD (§Suspension): opening reads every group out of the store.
        // A shipped iOS build was killed with this very call inside `pread`.
        openHandle = try MLSClient.held { () throws -> OpaquePointer in
            var created: OpaquePointer?
            let status = withBytes(credential) { credentialBytes, credentialLength in
                withBytes(signatureSeed) { seedBytes, seedLength in
                    trustedKeysJSON.withCString { json in
                        // `withOptionalCString` rather than a branch: the C door
                        // takes NULL for "no file", so nil has a spelling here and
                        // does not need a second call site.
                        withOptionalCString(storePath) { path in
                            withOptionalBytes(storeKey) { keyBytes, keyLength in
                                withOptionalBytes(ownAccountIdentity) { ownBytes, ownLength in
                                    (storeMustExist
                                        ? peachy_mls_client_open_existing
                                        : peachy_mls_client_open)(
                                        credentialBytes,
                                        credentialLength,
                                        seedBytes,
                                        seedLength,
                                        json,
                                        path,
                                        keyBytes,
                                        keyLength,
                                        ownBytes,
                                        ownLength,
                                        &created
                                    )
                                }
                            }
                        }
                    }
                }
            }
            guard status == PEACHY_MLS_OK, let created else {
                throw MLSError(code: MLSError.Code(status), message: lastErrorMessage())
            }
            return created
        }
    }

    /// The same, with the store named as a file URL — and put on disk properly.
    ///
    /// Three things this does that the path initializer cannot:
    ///
    ///  1. creates the containing directory, because SQLite will not;
    ///  2. marks the database and its `-wal`/`-shm` siblings
    ///     `isExcludedFromBackup`, for the same reason `DeviceKeyStore` and
    ///     `LocalDatabase` do it in the Apple apps' shared code — this file holds a
    ///     device's ratchet secrets, and a device's secrets restored onto a
    ///     SECOND device would be two members of every group sharing one leaf,
    ///     which MLS has no way to survive. It is not a backup of your chats;
    ///     it is a key that must not be copied;
    ///  3. leaves the exclusion attempt best-effort, matching `LocalDatabase`.
    ///     A failure to set a resource value on a volume that has no such
    ///     attribute is not a reason to refuse to start the app.
    ///
    /// - Parameter storeURL: a file URL. `storeURL(forDevice:in:)` gives the
    ///   conventional one.
    public convenience init(
        credential: Data,
        signatureSeed: Data,
        trustedKeysJSON: String,
        storeURL: URL,
        storeKey: Data? = nil,
        ownAccountIdentity: Data? = nil
    ) throws {
        try FileManager.default.createDirectory(
            at: storeURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try self.init(
            credential: credential,
            signatureSeed: signatureSeed,
            trustedKeysJSON: trustedKeysJSON,
            storePath: storeURL.path,
            storeKey: storeKey,
            ownAccountIdentity: ownAccountIdentity
        )
        MLSClient.excludeFromBackup(storeURL)
    }

    /// Where a device's MLS store conventionally lives.
    ///
    /// Application Support, not Caches: the system may evict Caches under
    /// pressure, and an evicted MLS store is every group gone. Per device id,
    /// because two accounts on one phone are two devices with two sets of
    /// leaves.
    ///
    /// - Parameter directory: override the container, for tests. The default is
    ///   this app's Application Support directory.
    public static func storeURL(forDevice deviceID: String, in directory: URL? = nil) -> URL {
        let container =
            directory
            ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
                .first
            ?? FileManager.default.temporaryDirectory
        return
            container
            .appendingPathComponent("PeachyMLS", isDirectory: true)
            .appendingPathComponent("\(deviceID).sqlite", isDirectory: false)
    }

    /// Delete a device's MLS store and its journal files. For DELETING THE
    /// ACCOUNT, not for signing out (`docs/sealed-messages.md` §Sign-out).
    ///
    /// Every group's secrets go with it, which is the point: state left behind
    /// after an account is deleted is state somebody else's session could be
    /// restored to. Signing out deliberately leaves it, because the same person
    /// signing back in on the same device has to come back as the same MLS
    /// device or every group they are in needs a fresh Welcome.
    ///
    /// **Call ``close()`` on any client over this file first.** Unlinking a
    /// SQLite database out from under an open connection leaves the `-wal` and
    /// `-shm` behind — the connection recreates them — so the "destroyed" store
    /// comes back as a torn one.
    public static func destroyStore(at storeURL: URL) {
        for file in storeFiles(storeURL) {
            try? FileManager.default.removeItem(at: file)
        }
    }

    /// The database and the two files WAL mode puts beside it. All three carry
    /// content — the `-wal` holds committed transactions not yet checkpointed —
    /// so anything done to one is done to all three.
    private static func storeFiles(_ storeURL: URL) -> [URL] {
        // SQLite names them by appending to the WHOLE path, extension included:
        // `peachy.sqlite-wal`, not `peachy-wal.sqlite`. Hence string
        // concatenation rather than `appendingPathExtension`, which would put
        // the suffix after a dot and name two files that do not exist.
        [
            storeURL,
            URL(fileURLWithPath: storeURL.path + "-wal"),
            URL(fileURLWithPath: storeURL.path + "-shm"),
        ]
    }

    private static func excludeFromBackup(_ storeURL: URL) {
        for var file in storeFiles(storeURL)
        where FileManager.default.fileExists(atPath: file.path) {
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try? file.setResourceValues(values)
        }
    }

    /// Close the client now, freeing the handle and every group's key material
    /// with it, and releasing the SQLite file. Idempotent.
    ///
    /// `deinit` does this too, so an app that simply drops its reference is
    /// fine. What `deinit` cannot give you is a MOMENT: ARC frees when the last
    /// reference goes, which is not the same as when you stopped holding one,
    /// and a caller that needs the store closed before it does something to the
    /// FILE needs to say when. ``destroyStore(at:)`` is exactly that caller —
    /// unlinking a SQLite database out from under an open connection leaves the
    /// `-wal` and `-shm` behind to be recreated, and on a platform with file
    /// locking it can fail outright. Kotlin's `MlsClient.close()` is the twin
    /// of this, and the ordering it documents is the ordering here.
    ///
    /// Every method throws ``MLSError/closed`` afterward, rather than
    /// dereferencing a freed pointer.
    public func close() {
        // Held: freeing commits anything still open and closes the SQLite
        // connection, which as the last one on the file checkpoints the WAL.
        MLSClient.heldQuietly {
            lock.lock()
            defer { lock.unlock() }
            guard let open = openHandle else { return }
            // Cleared BEFORE the free, so a throw out of the free — there is
            // none, but the rule should not depend on that — cannot leave a
            // dangling handle another call would dereference.
            openHandle = nil
            peachy_mls_client_free(open)
        }
    }

    /// True while this client is usable; false after ``close()``.
    public var isOpen: Bool {
        lock.lock()
        defer { lock.unlock() }
        return openHandle != nil
    }

    deinit {
        // Frees every group's key material with it. There is no other owner:
        // the handle never leaves this class. No lock: `deinit` runs when the
        // last reference is gone, so nobody else can be inside the object.
        if let open = openHandle {
            MLSClient.heldQuietly { peachy_mls_client_free(open) }
        }
    }

    /// The version of `peachy-mls-core` the linked library was built from.
    public static var coreVersion: String {
        String(cString: peachy_mls_version())
    }

    /// The ABI version the linked library was built with
    /// (`peachy_mls_abi_version`).
    public static var abiVersion: UInt32 {
        peachy_mls_abi_version()
    }

    /// The ABI version the header this package compiled against describes
    /// (`PEACHY_MLS_ABI_VERSION`).
    public static var headerABIVersion: UInt32 {
        UInt32(PEACHY_MLS_ABI_VERSION)
    }

    /// Whether the linked library speaks the ABI this package was compiled
    /// against. An app checks it before any other call and refuses to run on
    /// a mismatch: a library of another ABI reads structs and constants this
    /// package lays out differently.
    public static var abiMatches: Bool {
        abiVersion == headerABIVersion
    }

    /// ENCRYPT A STORE IN PLACE (`peachy_mls_store_encrypt_in_place`): the
    /// store at `path`, written in the clear, becomes one under `key` (32
    /// bytes, or 48 for the plaintext-header layout, as `storeKey` takes it),
    /// with every row kept. The answer to `.plaintextStore`. Throws
    /// `.invalidArgument`, with nothing changed, for a path with no store or
    /// a store that is not in the clear, and `.insecureStore` for one whose
    /// files group or others can write, or that is a symbolic link. A failure part-way leaves the store
    /// in the clear, as it was: call it again. Close every client over the
    /// file first.
    public static func encryptStoreInPlace(path: String, key: Data) throws {
        try MLSClient.held {
            try path.withCString { pathPointer in
                try withBytes(key) { keyBytes, keyLength in
                    try checkStatus(peachy_mls_store_encrypt_in_place(pathPointer, keyBytes, keyLength))
                }
            }
        }
    }

    /// How many devices, this one included, one founding commit seats
    /// (``seatFounding(groupID:keyPackages:ownKeyPackage:)``).
    public static var foundingSeats: Int {
        Int(peachy_mls_founding_seats())
    }

    /// How far the server's clock is ahead of this device's, in milliseconds
    /// (negative when behind), as the app last measured it from a
    /// `FetchMailbox` reply's `server_time` against the midpoint of the
    /// request's send and its reply's arrival. Process-wide: every client
    /// stamps and judges the live call lane's frames and typing's on this
    /// device's clock plus the offset, so a device whose own clock is off
    /// still agrees with its peers. The core clamps it to ±1 day; credential
    /// checks stay on the device's own clock. 0 until set.
    public static var serverClockOffsetMs: Int64 {
        get { peachy_mls_server_clock_offset_ms() }
        set { peachy_mls_set_server_clock_offset_ms(newValue) }
    }

    // MARK: - Carried server keys
    //
    // Every build carries the server keys that sign device credentials
    // (`mls/core/pinned-server-keys.json`); these read a published list
    // against them. `server` is "production" for the production API and
    // "development" for any other.

    /// The published list (the body of `GET /healthz/device-credential-keys`)
    /// read against the carried set: empty when they match, else one line
    /// naming the kids that differ, for this device's log only.
    public static func serverKeyPinReport(publishedJSON: String, server: String) throws -> String {
        var buffer = PeachyMlsBuffer()
        try publishedJSON.withCString { json in
            try server.withCString { name in
                try checkStatus(peachy_mls_server_key_pin_report(json, name, &buffer))
            }
        }
        return takeString(&buffer)
    }

    /// The published list narrowed to the keys the carried set holds under
    /// the same bytes, in the same shape: what to trust once pinning is
    /// enforced.
    public static func serverKeysPinned(publishedJSON: String, server: String) throws -> String {
        var buffer = PeachyMlsBuffer()
        try publishedJSON.withCString { json in
            try server.withCString { name in
                try checkStatus(peachy_mls_server_keys_pinned(json, name, &buffer))
            }
        }
        return takeString(&buffer)
    }

    // MARK: - Enrollment
    //
    // These two come BEFORE there is a client, and the ordering is
    // load-bearing: make a seed, publish ``signingKeyPublicKey(seed:)`` of it
    // as `RegisterDevice`'s `signing_key`, take the credential the server mints
    // against it, and only then call ``init(credential:signingKeySeed:...)``.
    // A client opened with a seed no credential was minted for throws
    // `leafKeyMismatch` on every call — which reads as a protocol bug and is
    // really this sequence run out of order.

    /// A fresh 32-byte device signing key seed, from the platform CSPRNG.
    ///
    /// The seed belongs in the Keychain and never on the wire. It is a RAW
    /// seed rather than a `SecKey` the Secure Enclave would only use on the
    /// caller's behalf, and that is a real weakening with a reason: every
    /// signing site inside OpenMLS is synchronous and takes key bytes, so
    /// there is no seam in the core where a signature could be delegated back
    /// out (docs/identity.md §Security considerations).
    public static func generateSigningKeySeed() throws -> Data {
        var buffer = PeachyMlsBuffer()
        try checkStatus(peachy_mls_generate_signing_key_seed(&buffer))
        return takeData(&buffer)
    }

    /// The raw Ed25519 public key for a seed — which is also the leaf
    /// signature key and the `device_key` the credential binds. Three names,
    /// one 32 bytes.
    public static func signingKeyPublicKey(seed: Data) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try withBytes(seed) { bytes, length in
            try checkStatus(peachy_mls_signing_key_public_key(bytes, length, &buffer))
        }
        return takeData(&buffer)
    }

    // MARK: - Device linking
    //
    // Approving a new device from one you already have, the QR code that
    // carries its key past the server, and the commit-then-reveal two-digit
    // number. Statics, like the enrollment pair above and for the same reason:
    // they are about PUBLIC KEYS and nonces and nothing else, so there is no
    // client, no group and no lock to take.
    //
    // **Read `mls/core/src/device_link.rs`'s header before deciding when to
    // reveal a nonce.** What an approving iPhone signs is a public key the
    // SERVER handed it, so the key has to cross once through the person:
    // scanned, or compared as a number the approver committed to before the new
    // device drew its half.

    /// The exact bytes an approving device signs to vouch for another device:
    /// `"peachy-device-approval-v1" || 0x00 || deviceId || 0x00 || signingKey`.
    ///
    /// `deviceId` is `devices.id` and `signingKey` is the approved device's raw
    /// 32-byte Ed25519 public key. Throws `invalidArgument` for an empty id or
    /// a key of the wrong length, naming the field and the size it wanted.
    public static func deviceApprovalStatement(deviceId: String, signingKey: Data) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try deviceId.withCString { id in
            try withBytes(signingKey) { key, keyLength in
                try checkStatus(
                    peachy_mls_device_approval_statement(id, key, keyLength, &buffer)
                )
            }
        }
        return takeData(&buffer)
    }

    /// Sign that statement with this device's own signing seed — the same seed
    /// ``signingKeyPublicKey(seed:)`` takes, out of the Keychain.
    ///
    /// Ed25519 is deterministic, so the same inputs always produce the same 64
    /// bytes; `mls/fixtures/device-link.json` pins several of them.
    public static func signDeviceApproval(
        seed: Data,
        deviceId: String,
        signingKey: Data
    ) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try deviceId.withCString { id in
            try withBytes(seed) { seedBytes, seedLength in
                try withBytes(signingKey) { key, keyLength in
                    try checkStatus(
                        peachy_mls_sign_device_approval(
                            seedBytes, seedLength, id, key, keyLength, &buffer
                        )
                    )
                }
            }
        }
        return takeData(&buffer)
    }

    /// Whether `signature` is a genuine approval of `(deviceId, signingKey)` by
    /// the holder of `approverKey`.
    ///
    /// **Non-throwing, and that is the design rather than a convenience.** A
    /// malformed approver key, a signature of the wrong length and a signature
    /// that simply did not check out all mean one thing to a caller: this
    /// approval does not hold. A refusal from the C layer is therefore `false`
    /// and not an error — a caller able to tell those apart would be holding an
    /// oracle, and every call site would have to decide for itself which
    /// failures are safe to read as "no".
    public static func verifyDeviceApproval(
        approverKey: Data,
        deviceId: String,
        signingKey: Data,
        signature: Data
    ) -> Bool {
        var valid = false
        // -1 is no status this ABI defines, which is the point: it is what the
        // variable reads as if the call below never happened.
        var status: Int32 = -1
        withUnsafeMutablePointer(to: &valid) { out in
            deviceId.withCString { id in
                withBytes(approverKey) { approver, approverLength in
                    withBytes(signingKey) { key, keyLength in
                        withBytes(signature) { bytes, length in
                            status = peachy_mls_verify_device_approval(
                                approver, approverLength,
                                id,
                                key, keyLength,
                                bytes, length,
                                out
                            )
                        }
                    }
                }
            }
        }
        return status == PEACHY_MLS_OK && valid
    }

    /// The approver's 32-byte commitment to its 32-byte nonce, published before
    /// the new device draws its own.
    public static func deviceLinkCommitment(approverNonce: Data) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try withBytes(approverNonce) { nonce, length in
            try checkStatus(peachy_mls_device_link_commitment(nonce, length, &buffer))
        }
        return takeData(&buffer)
    }

    /// The two-digit number both devices show, `"00"` to `"99"`.
    ///
    /// Throws `invalidArgument` for any input that is not 32 bytes, for two
    /// identical keys, and for an approver nonce that does not open the
    /// commitment — never a number in those cases.
    public static func deviceLinkNumber(
        newDeviceKey: Data,
        approverKey: Data,
        approverCommitment: Data,
        deviceNonce: Data,
        approverNonce: Data
    ) throws -> String {
        var buffer = PeachyMlsBuffer()
        try withBytes(newDeviceKey) { k, kLength in
            try withBytes(approverKey) { a, aLength in
                try withBytes(approverCommitment) { c, cLength in
                    try withBytes(deviceNonce) { n, nLength in
                        try withBytes(approverNonce) { r, rLength in
                            try checkStatus(
                                peachy_mls_device_link_number(
                                    k, kLength, a, aLength, c, cLength, n, nLength, r, rLength,
                                    &buffer
                                )
                            )
                        }
                    }
                }
            }
        }
        return takeString(&buffer)
    }

    /// The approver's two-digit number: what the APPROVING device shows after
    /// a correct pick, for the person to pick on the new device. The same
    /// inputs and throws as ``deviceLinkNumber(newDeviceKey:approverKey:approverCommitment:deviceNonce:approverNonce:)``,
    /// under another domain.
    public static func deviceLinkApproverNumber(
        newDeviceKey: Data,
        approverKey: Data,
        approverCommitment: Data,
        deviceNonce: Data,
        approverNonce: Data
    ) throws -> String {
        var buffer = PeachyMlsBuffer()
        try withBytes(newDeviceKey) { k, kLength in
            try withBytes(approverKey) { a, aLength in
                try withBytes(approverCommitment) { c, cLength in
                    try withBytes(deviceNonce) { n, nLength in
                        try withBytes(approverNonce) { r, rLength in
                            try checkStatus(
                                peachy_mls_device_link_approver_number(
                                    k, kLength, a, aLength, c, cLength, n, nLength, r, rLength,
                                    &buffer
                                )
                            )
                        }
                    }
                }
            }
        }
        return takeString(&buffer)
    }

    /// The text the new device's QR code carries:
    /// `"peachy-link:" + deviceId + "/" + hex(signingKey) + "/" + hex(linkSecret)`,
    /// where `linkSecret` is 32 random bytes this device drew for the pairing
    /// and keeps to itself.
    public static func deviceLinkQR(deviceId: String, signingKey: Data, linkSecret: Data) throws -> String {
        var buffer = PeachyMlsBuffer()
        try deviceId.withCString { id in
            try withBytes(signingKey) { key, keyLength in
                try withBytes(linkSecret) { secret, secretLength in
                    try checkStatus(
                        peachy_mls_device_link_qr(id, key, keyLength, secret, secretLength, &buffer)
                    )
                }
            }
        }
        return takeString(&buffer)
    }

    /// The 32-byte link secret a scanned QR code carries, when the code names
    /// exactly this waiting device and key; `nil` for any other code.
    public static func deviceLinkQRSecret(scanned: String, deviceId: String, signingKey: Data) -> Data? {
        var buffer = PeachyMlsBuffer()
        var status: Int32 = -1
        scanned.withCString { text in
            deviceId.withCString { id in
                withBytes(signingKey) { key, keyLength in
                    status = peachy_mls_device_link_qr_secret(text, id, key, keyLength, &buffer)
                }
            }
        }
        let secret = takeData(&buffer)
        return status == PEACHY_MLS_OK && secret.count == 32 ? secret : nil
    }

    /// Whether a scanned QR code names exactly this waiting device and key.
    /// Non-throwing, for the reason ``verifyDeviceApproval(approverKey:deviceId:signingKey:signature:)``
    /// gives: every way it fails means "not this one".
    public static func deviceLinkQRMatches(scanned: String, deviceId: String, signingKey: Data) -> Bool {
        var matches = false
        var status: Int32 = -1
        withUnsafeMutablePointer(to: &matches) { out in
            scanned.withCString { text in
                deviceId.withCString { id in
                    withBytes(signingKey) { key, keyLength in
                        status = peachy_mls_device_link_qr_matches(text, id, key, keyLength, out)
                    }
                }
            }
        }
        return status == PEACHY_MLS_OK && matches
    }

    /// THE WAITING DEVICE'S RULE for the two-digit number: one exchange per
    /// pairing. `bound*` is what this pairing already answered — `""` and two
    /// empty `Data` for nothing yet. Throws `invalidArgument` for an empty
    /// approver id, a key or commitment not 32 bytes, or half a binding; a
    /// caller skips that exchange.
    public static func deviceLinkWaiterStep(
        boundApproverId: String,
        boundApproverKey: Data,
        boundCommitment: Data,
        approverId: String,
        approverKey: Data,
        commitment: Data
    ) throws -> DeviceLinkWaiterStep {
        var step: UInt32 = .max
        try boundApproverId.withCString { boundId in
            try withBytes(boundApproverKey) { bk, bkLength in
                try withBytes(boundCommitment) { bc, bcLength in
                    try approverId.withCString { id in
                        try withBytes(approverKey) { k, kLength in
                            try withBytes(commitment) { c, cLength in
                                try checkStatus(
                                    peachy_mls_device_link_waiter_step(
                                        boundId, bk, bkLength, bc, bcLength,
                                        id, k, kLength, c, cLength,
                                        &step
                                    )
                                )
                            }
                        }
                    }
                }
            }
        }
        // A code this build does not know answers nothing more.
        return DeviceLinkWaiterStep(rawValue: step) ?? .interrupted
    }

    /// Sign this approver's commitment for one waiting device: 64
    /// deterministic bytes, posted beside the commitment. The waiting device
    /// answers only an exchange whose signature holds.
    public static func signDeviceLinkCommitment(
        seed: Data,
        pendingDeviceId: String,
        pendingKey: Data,
        commitment: Data
    ) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try pendingDeviceId.withCString { id in
            try withBytes(seed) { s, sLength in
                try withBytes(pendingKey) { k, kLength in
                    try withBytes(commitment) { c, cLength in
                        try checkStatus(
                            peachy_mls_sign_device_link_commitment(
                                s, sLength, id, k, kLength, c, cLength, &buffer
                            )
                        )
                    }
                }
            }
        }
        return takeData(&buffer)
    }

    /// Whether `signature` is `approverKey`'s signature over `commitment` for
    /// the waiting device `(pendingDeviceId, pendingKey)`. Non-throwing: every
    /// way it can fail to hold is `false`, as for ``verifyDeviceApproval(approverKey:deviceId:signingKey:signature:)``.
    public static func verifyDeviceLinkCommitment(
        approverKey: Data,
        pendingDeviceId: String,
        pendingKey: Data,
        commitment: Data,
        signature: Data
    ) -> Bool {
        var valid = false
        var status: Int32 = -1
        withUnsafeMutablePointer(to: &valid) { out in
            pendingDeviceId.withCString { id in
                withBytes(approverKey) { a, aLength in
                    withBytes(pendingKey) { k, kLength in
                        withBytes(commitment) { c, cLength in
                            withBytes(signature) { s, sLength in
                                status = peachy_mls_verify_device_link_commitment(
                                    a, aLength, id, k, kLength, c, cLength, s, sLength, out
                                )
                            }
                        }
                    }
                }
            }
        }
        return status == PEACHY_MLS_OK && valid
    }

    /// A fresh 32-byte link-key seed. The waiting device draws one per
    /// pairing and keeps it until its account key arrives.
    public static func generateDeviceLinkKemSeed() throws -> Data {
        var buffer = PeachyMlsBuffer()
        try checkStatus(peachy_mls_generate_device_link_kem_seed(&buffer))
        return takeData(&buffer)
    }

    /// The 1216-byte X-Wing link key a 32-byte seed derives, posted beside
    /// the waiting device's nonce.
    public static func deviceLinkKemPublicKey(seed: Data) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try withBytes(seed) { s, sLength in
            try checkStatus(peachy_mls_device_link_kem_public_key(s, sLength, &buffer))
        }
        return takeData(&buffer)
    }

    /// The waiting device's signature over the link key it posts with its
    /// nonce: 64 deterministic bytes under its own Ed25519 seed, the key the
    /// two-digit number is derived over.
    public static func signDeviceLinkKem(
        seed: Data,
        pendingDeviceId: String,
        commitment: Data,
        deviceNonce: Data,
        linkKey: Data
    ) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try pendingDeviceId.withCString { id in
            try withBytes(seed) { s, sLength in
                try withBytes(commitment) { c, cLength in
                    try withBytes(deviceNonce) { n, nLength in
                        try withBytes(linkKey) { k, kLength in
                            try checkStatus(
                                peachy_mls_sign_device_link_kem(
                                    s, sLength, id, c, cLength, n, nLength, k, kLength, &buffer
                                )
                            )
                        }
                    }
                }
            }
        }
        return takeData(&buffer)
    }

    /// Whether `signature` is the waiting device's (`pendingKey`, the key the
    /// number was derived over) signature over `linkKey` for this exchange.
    /// Non-throwing: every way it can fail to hold is `false`, an empty link
    /// key included.
    public static func verifyDeviceLinkKem(
        pendingKey: Data,
        pendingDeviceId: String,
        commitment: Data,
        deviceNonce: Data,
        linkKey: Data,
        signature: Data
    ) -> Bool {
        var valid = false
        var status: Int32 = -1
        withUnsafeMutablePointer(to: &valid) { out in
            pendingDeviceId.withCString { id in
                withBytes(pendingKey) { p, pLength in
                    withBytes(commitment) { c, cLength in
                        withBytes(deviceNonce) { n, nLength in
                            withBytes(linkKey) { k, kLength in
                                withBytes(signature) { s, sLength in
                                    status = peachy_mls_verify_device_link_kem(
                                        p, pLength, id, c, cLength, n, nLength,
                                        k, kLength, s, sLength, out
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
        return status == PEACHY_MLS_OK && valid
    }

    /// THE APPROVING DEVICE'S RULE for the two-digit number: fix the waiting
    /// device's nonce before revealing, and treat any change after that as an
    /// interruption. `pendingKey`, `commitment` and `boundDeviceNonce` are the
    /// caller's own state for one prompt (`boundDeviceNonce` empty until the
    /// first `.reveal`, when the caller stores `listedDeviceNonce` as it BEFORE
    /// posting). The `listed*` values are this read, empty when absent. Throws
    /// `invalidArgument` for a malformed pending key, commitment or bound nonce.
    public static func deviceLinkApproverStep(
        pendingKey: Data,
        commitment: Data,
        boundDeviceNonce: Data,
        listedKey: Data,
        listedCommitment: Data,
        listedDeviceNonce: Data,
        listedApproverNonce: Data
    ) throws -> DeviceLinkApproverStep {
        var step: UInt32 = .max
        try withBytes(pendingKey) { pk, pkLength in
            try withBytes(commitment) { c, cLength in
                try withBytes(boundDeviceNonce) { b, bLength in
                    try withBytes(listedKey) { lk, lkLength in
                        try withBytes(listedCommitment) { lc, lcLength in
                            try withBytes(listedDeviceNonce) { ln, lnLength in
                                try withBytes(listedApproverNonce) { la, laLength in
                                    try checkStatus(
                                        peachy_mls_device_link_approver_step(
                                            pk, pkLength, c, cLength, b, bLength,
                                            lk, lkLength, lc, lcLength, ln, lnLength,
                                            la, laLength, &step
                                        )
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
        // A code this build does not know shows nothing.
        return DeviceLinkApproverStep(rawValue: step) ?? .interrupted
    }

    // MARK: - The account identity key
    //
    // One Ed25519 key per account, derived from the account store's key, that
    // signs for each of the account's devices. Every peer refuses a leaf
    // without its certificate (docs/identity.md §The account identity key).

    /// The account's 32-byte public identity key, derived from its 32-byte
    /// account key: what `RegisterDevice` publishes as the account identity.
    public static func accountIdentityPublicKey(accountKey: Data) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try withBytes(accountKey) { key, length in
            try checkStatus(peachy_mls_account_identity_public_key(key, length, &buffer))
        }
        return takeData(&buffer)
    }

    /// The account identity key's 64-byte signature over `deviceKey`.
    public static func signAccountDevice(accountKey: Data, deviceKey: Data) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try withBytes(accountKey) { account, accountLength in
            try withBytes(deviceKey) { device, deviceLength in
                try checkStatus(
                    peachy_mls_sign_account_device(account, accountLength, device, deviceLength, &buffer)
                )
            }
        }
        return takeData(&buffer)
    }

    /// The account identity key's 64-byte signature REVOKING `deviceKey`: what
    /// `RevokeDevice` sends for each row of the removed install, so a peer
    /// removes its leaf on the account's word rather than the server's.
    public static func signDeviceRevocation(accountKey: Data, deviceKey: Data) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try withBytes(accountKey) { account, accountLength in
            try withBytes(deviceKey) { device, deviceLength in
                try checkStatus(
                    peachy_mls_sign_device_revocation(
                        account, accountLength, device, deviceLength, &buffer)
                )
            }
        }
        return takeData(&buffer)
    }

    /// Whether `signature` is `accountIdentityKey` vouching for `deviceKey`.
    /// Non-throwing for the reason ``verifyDeviceApproval(approverKey:deviceId:signingKey:signature:)`` is.
    public static func verifyAccountDevice(
        accountIdentityKey: Data,
        deviceKey: Data,
        signature: Data
    ) -> Bool {
        var valid = false
        var status: Int32 = -1
        withUnsafeMutablePointer(to: &valid) { out in
            withBytes(accountIdentityKey) { account, accountLength in
                withBytes(deviceKey) { device, deviceLength in
                    withBytes(signature) { bytes, length in
                        status = peachy_mls_verify_account_device(
                            account, accountLength,
                            device, deviceLength,
                            bytes, length,
                            out
                        )
                    }
                }
            }
        }
        return status == PEACHY_MLS_OK && valid
    }

    // MARK: - The encrypted account store
    //
    // `peachy_mls_core::account_store`, through five unconditional C entry
    // points. Statics, like device linking: pure functions over bytes, no
    // client and no lock. Every refusal throws `invalidArgument`; an open that
    // fails because the key, id, approver or device id is wrong, or because
    // the bytes were altered, says "does not open" and nothing more specific.
    //
    // **`approverSigningKey` must come from a device on this one's own
    // approver list** (approved, unrevoked, published) — never from
    // the response that carried the box. The box authenticates the approver;
    // that only means something if the approver key is one a person vouched
    // for. `mls/core/src/account_store.rs`'s header has the whole argument.

    /// A fresh 32-byte account key from the platform CSPRNG.
    public static func generateAccountKey() throws -> Data {
        var buffer = PeachyMlsBuffer()
        try checkStatus(peachy_mls_generate_account_key(&buffer))
        return takeData(&buffer)
    }

    /// Seal `accountKey` as a version-1 (X25519-only) box. `approverSeed` is
    /// THIS device's Ed25519 seed; `recipientSigningKey` the new device's
    /// 32-byte public key; `deviceId` its `devices.id`. Returns the 93-byte
    /// box. Only a device with its own server-approval switch on opens one: a
    /// device a person approves takes only the version-3 box
    /// (`accountKeySealHybrid`). For a server-run approver (a test server, or
    /// the store-review login's anchor).
    public static func accountKeySeal(
        approverSeed: Data,
        recipientSigningKey: Data,
        deviceId: String,
        accountKey: Data
    ) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try deviceId.withCString { id in
            try withBytes(approverSeed) { seed, seedLength in
                try withBytes(recipientSigningKey) { key, keyLength in
                    try withBytes(accountKey) { account, accountLength in
                        try checkStatus(
                            peachy_mls_account_key_seal(
                                seed, seedLength, key, keyLength, id,
                                account, accountLength, &buffer
                            )
                        )
                    }
                }
            }
        }
        return takeData(&buffer)
    }

    /// Seal `accountKey` for a new device that posted a link key: the
    /// post-quantum version-3 box. `recipientLinkKey` is the 1216-byte key the
    /// waiting device posted, which the caller MUST have checked with
    /// ``verifyDeviceLinkKem(pendingKey:pendingDeviceId:commitment:deviceNonce:linkKey:signature:)``.
    /// Returns the 1213-byte box.
    public static func accountKeySealHybrid(
        approverSeed: Data,
        recipientSigningKey: Data,
        recipientLinkKey: Data,
        deviceId: String,
        accountKey: Data
    ) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try deviceId.withCString { id in
            try withBytes(approverSeed) { seed, seedLength in
                try withBytes(recipientSigningKey) { key, keyLength in
                    try withBytes(recipientLinkKey) { link, linkLength in
                        try withBytes(accountKey) { account, accountLength in
                            try checkStatus(
                                peachy_mls_account_key_seal_hybrid(
                                    seed, seedLength, key, keyLength, link, linkLength, id,
                                    account, accountLength, &buffer
                                )
                            )
                        }
                    }
                }
            }
        }
        return takeData(&buffer)
    }

    /// THE NEW DEVICE'S DOOR for its account key: the version-3 box, and the
    /// version-1 box only when `serverApprovalAllowed`. `linkKeySeed` is the
    /// seed of the link key this device posted (empty for none);
    /// `confirmedApproverKey` the approver whose number the person picked on
    /// this device (empty for none); `serverApprovalAllowed` this device's own
    /// switch, never set from anything the server says. Returns the 32-byte
    /// account key.
    public static func accountKeyAcceptHybrid(
        recipientSeed: Data,
        approverSigningKey: Data,
        deviceId: String,
        box: Data,
        linkKeySeed: Data,
        confirmedApproverKey: Data,
        serverApprovalAllowed: Bool
    ) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try deviceId.withCString { id in
            try withBytes(recipientSeed) { seed, seedLength in
                try withBytes(approverSigningKey) { key, keyLength in
                    try withBytes(box) { sealed, sealedLength in
                        try withBytes(linkKeySeed) { link, linkLength in
                            try withBytes(confirmedApproverKey) { confirmed, confirmedLength in
                                try checkStatus(
                                    peachy_mls_account_key_accept_hybrid(
                                        seed, seedLength, key, keyLength, id,
                                        sealed, sealedLength, link, linkLength,
                                        confirmed, confirmedLength, serverApprovalAllowed,
                                        &buffer
                                    )
                                )
                            }
                        }
                    }
                }
            }
        }
        return takeData(&buffer)
    }

    /// Open a version-1 account-key box with no check of who sealed it.
    /// `recipientSeed` is THIS device's seed; `deviceId` this device's own
    /// `devices.id`. Returns the 32-byte account key. For tests and tools:
    /// only an archive built with the `fixture` feature opens anything here,
    /// and every other build throws `unsupported`. A new device takes its
    /// key through
    /// ``accountKeyAcceptHybrid(recipientSeed:approverSigningKey:deviceId:box:linkKeySeed:confirmedApproverKey:serverApprovalAllowed:)``.
    public static func accountKeyOpen(
        recipientSeed: Data,
        approverSigningKey: Data,
        deviceId: String,
        box: Data
    ) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try deviceId.withCString { id in
            try withBytes(recipientSeed) { seed, seedLength in
                try withBytes(approverSigningKey) { key, keyLength in
                    try withBytes(box) { sealed, sealedLength in
                        try checkStatus(
                            peachy_mls_account_key_open(
                                seed, seedLength, key, keyLength, id,
                                sealed, sealedLength, &buffer
                            )
                        )
                    }
                }
            }
        }
        return takeData(&buffer)
    }

    /// Seal a history hand-off's 32-byte attachment `key` to the device it is
    /// handed to: `recipientSigningKey` is that device's Ed25519 public key
    /// (the one this device just vouched for), `deviceId` its `devices.id`.
    /// Returns the 93-byte box, the pointer's `kb`.
    public static func transferKeySeal(
        recipientSigningKey: Data,
        deviceId: String,
        key: Data
    ) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try deviceId.withCString { id in
            try withBytes(recipientSigningKey) { recipient, recipientLength in
                try withBytes(key) { keyBytes, keyLength in
                    try checkStatus(
                        peachy_mls_transfer_key_seal(
                            recipient, recipientLength, id, keyBytes, keyLength, &buffer
                        )
                    )
                }
            }
        }
        return takeData(&buffer)
    }

    /// Open a transfer-key box on the device it was sealed to: `recipientSeed`
    /// is THIS device's seed and `deviceId` its own `devices.id`. Returns the
    /// 32-byte attachment key; a box sealed to any other device or row, or an
    /// account-key box, throws.
    public static func transferKeyOpen(
        recipientSeed: Data,
        deviceId: String,
        box: Data
    ) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try deviceId.withCString { id in
            try withBytes(recipientSeed) { seed, seedLength in
                try withBytes(box) { sealed, sealedLength in
                    try checkStatus(
                        peachy_mls_transfer_key_open(
                            seed, seedLength, id, sealed, sealedLength, &buffer
                        )
                    )
                }
            }
        }
        return takeData(&buffer)
    }

    /// Seal `plaintext` (at most 65536 bytes, the manifest 360000; empty is
    /// fine) as the value stored under the 16-byte `id`. The manifest uses
    /// sixteen zero bytes.
    public static func storeSeal(accountKey: Data, id: Data, plaintext: Data) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try withBytes(accountKey) { key, keyLength in
            try withBytes(id) { idBytes, idLength in
                try withBytes(plaintext) { bytes, length in
                    try checkStatus(
                        peachy_mls_store_seal(
                            key, keyLength, idBytes, idLength, bytes, length, &buffer
                        )
                    )
                }
            }
        }
        return takeData(&buffer)
    }

    /// Open a value ``storeSeal(accountKey:id:plaintext:)`` made under the
    /// same account key and id. An empty result is a real answer.
    public static func storeOpen(accountKey: Data, id: Data, value: Data) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try withBytes(accountKey) { key, keyLength in
            try withBytes(id) { idBytes, idLength in
                try withBytes(value) { bytes, length in
                    try checkStatus(
                        peachy_mls_store_open(
                            key, keyLength, idBytes, idLength, bytes, length, &buffer
                        )
                    )
                }
            }
        }
        return takeData(&buffer)
    }

    /// Seal a self-note under the account key and sign it as this device
    /// (format 0x02, domain "peachy self note v2"). `senderDeviceId` is this
    /// device's own `devices.id`, `issuedAtMs` its clock in unix
    /// milliseconds, and `deviceSeed` the 32-byte Ed25519 seed of the key
    /// that row carries.
    public static func noteSealSigned(
        accountKey: Data,
        id: Data,
        plaintext: Data,
        senderDeviceId: String,
        issuedAtMs: Int64,
        deviceSeed: Data
    ) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try senderDeviceId.withCString { sender in
            try withBytes(accountKey) { key, keyLength in
                try withBytes(id) { idBytes, idLength in
                    try withBytes(plaintext) { bytes, length in
                        try withBytes(deviceSeed) { seed, seedLength in
                            try checkStatus(
                                peachy_mls_note_seal_signed(
                                    key, keyLength, idBytes, idLength, bytes, length,
                                    sender, issuedAtMs, seed, seedLength, &buffer
                                )
                            )
                        }
                    }
                }
            }
        }
        return takeData(&buffer)
    }

    /// The device a signed note SAYS sent it: look it up in this device's own
    /// device list before ``noteOpenSigned(accountKey:id:value:senderDeviceId:senderSigningKey:nowMs:)``.
    /// Throws on a version-1 note, which names no sender.
    public static func noteSender(accountKey: Data, id: Data, value: Data) throws -> String {
        var buffer = PeachyMlsBuffer()
        try withBytes(accountKey) { key, keyLength in
            try withBytes(id) { idBytes, idLength in
                try withBytes(value) { bytes, length in
                    try checkStatus(
                        peachy_mls_note_sender(
                            key, keyLength, idBytes, idLength, bytes, length, &buffer
                        )
                    )
                }
            }
        }
        return String(decoding: takeData(&buffer), as: UTF8.self)
    }

    /// Open a signed note, believing it only when `senderDeviceId` sent it
    /// under `senderSigningKey` (the key this device's own list gives that
    /// device), issued at most seven days before `nowMs` and at most ten
    /// minutes after it.
    public static func noteOpenSigned(
        accountKey: Data,
        id: Data,
        value: Data,
        senderDeviceId: String,
        senderSigningKey: Data,
        nowMs: Int64
    ) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try senderDeviceId.withCString { sender in
            try withBytes(accountKey) { key, keyLength in
                try withBytes(id) { idBytes, idLength in
                    try withBytes(value) { bytes, length in
                        try withBytes(senderSigningKey) { signer, signerLength in
                            try checkStatus(
                                peachy_mls_note_open_signed(
                                    key, keyLength, idBytes, idLength, bytes, length,
                                    sender, signer, signerLength, nowMs, &buffer
                                )
                            )
                        }
                    }
                }
            }
        }
        return takeData(&buffer)
    }

    // MARK: - Handles and envelopes
    //
    // `peachy_mls_core::envelope`, for a member-rostered conversation
    // (docs/delivery.md §Handles and sender-addressed delivery).
    // The handle and the seal are statics: the group id is the key, so there
    // is no client and no lock. Opening is on the client, which tries every
    // group it holds.

    /// A conversation's handle, `SHA-256("peachy handle v1" ‖ groupId)`: the
    /// 32 bytes the server keys a member-rostered conversation by. The group
    /// id itself never reaches the server.
    public static func groupHandle(groupId: Data) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try withBytes(groupId) { bytes, length in
            try checkStatus(peachy_mls_group_handle(bytes, length, &buffer))
        }
        return takeData(&buffer)
    }

    /// A group message's epoch and content hint, read with no key
    /// (docs/sealed-messages.md §Content hints): what a receiver needs about a
    /// message that will not open. `epoch` is nil for bytes that are not a
    /// group message; `hint` is nil when it carries none this build knows.
    public static func peekMessage(_ message: Data) -> (epoch: UInt64?, hint: UInt8?) {
        var epoch: Int64 = -1
        var hint: Int32 = -1
        let status = try? withBytes(message) { bytes, length in
            try checkStatus(peachy_mls_peek_message(bytes, length, &epoch, &hint))
        }
        guard status != nil else { return (nil, nil) }
        return (epoch >= 0 ? UInt64(epoch) : nil, hint >= 0 ? UInt8(hint) : nil)
    }

    /// The author's commitment a group message carries (16 bytes), read with
    /// no key, or nil when it carries none (docs/sealed-messages.md
    /// §Asking for a message again).
    public static func peekCommitment(_ message: Data) -> Data? {
        var buffer = PeachyMlsBuffer()
        let status = try? withBytes(message) { bytes, length in
            try checkStatus(peachy_mls_peek_commitment(bytes, length, &buffer))
        }
        let commitment = takeData(&buffer)
        guard status != nil, commitment.count == 16 else { return nil }
        return commitment
    }

    /// The commitment to `actorId` as the author of a message whose secret is
    /// `secret`, in `groupId` (16 bytes): an answer to a resend ask is taken
    /// only when this, for its MLS sender and the secret it carries, equals
    /// what the unopened message carried.
    public static func resendAuthorCommitment(groupId: Data, actorId: String, secret: Data) throws
        -> Data
    {
        var buffer = PeachyMlsBuffer()
        try withBytes(groupId) { group, groupLength in
            try actorId.withCString { actor in
                try withBytes(secret) { bytes, length in
                    try checkStatus(
                        peachy_mls_resend_author_commitment(
                            group, groupLength, actor, bytes, length, &buffer))
                }
            }
        }
        return takeData(&buffer)
    }

    /// Wrap `inner` in the envelope that hides which conversation it belongs
    /// to, under a fresh random nonce, keyed by the group id: a seat ask or a
    /// link preview (``EnvelopeKind/seatAsk``, ``EnvelopeKind/linkPreview``)
    /// only. Any other value throws `invalidArgument`; a message, commit,
    /// typing frame or call signal is sealed by the client's own
    /// `sealEnvelope`, by the group's epoch.
    public static func sealEnvelope(groupId: Data, kind: UInt8, inner: Data) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try withBytes(groupId) { group, groupLength in
            try withBytes(inner) { bytes, length in
                try checkStatus(
                    peachy_mls_seal_envelope(group, groupLength, kind, bytes, length, &buffer)
                )
            }
        }
        return takeData(&buffer)
    }

    /// Open `envelope` as `groupId`'s, with no client: a group link's preview
    /// (``EnvelopeKind``'s link preview, docs/sealed-messages.md §The preview),
    /// read by a holder of the link who is not in the group. `nil` when it
    /// does not open.
    public static func openEnvelope(for groupId: Data, _ envelope: Data) throws -> OpenedEnvelope? {
        var inner = PeachyMlsBuffer()
        var kind: UInt8 = 0
        try withBytes(groupId) { group, groupLength in
            try withBytes(envelope) { bytes, length in
                try checkStatus(
                    peachy_mls_open_envelope_for(group, groupLength, bytes, length, &kind, &inner)
                )
            }
        }
        let innerBytes = takeData(&inner)
        guard kind != 0 else { return nil }
        return OpenedEnvelope(groupId: groupId, kind: kind, inner: innerBytes)
    }

    /// Open an envelope against every group this device holds.
    ///
    /// `nil` when none opens it — a conversation this device left, a tampered
    /// envelope, or bytes that are no envelope at all. That is an answer, not
    /// an error.
    public func openEnvelope(_ envelope: Data) throws -> OpenedEnvelope? {
        try locked { handle in
            var group = PeachyMlsBuffer()
            var inner = PeachyMlsBuffer()
            var kind: UInt8 = 0
            try withBytes(envelope) { bytes, length in
                try check(
                    peachy_mls_open_envelope(handle, bytes, length, &group, &kind, &inner)
                )
            }
            let groupId = takeData(&group)
            let innerBytes = takeData(&inner)
            // A group id is never empty, so empty is "none".
            guard !groupId.isEmpty, kind != 0 else { return nil }
            return OpenedEnvelope(groupId: groupId, kind: kind, inner: innerBytes)
        }
    }

    /// Keep a version 3 envelope that opened for no group here, so that it
    /// opens once this device holds the epoch it was sealed at: a copy that
    /// fell behind or forked meets these until a member returns its seat,
    /// and that Welcome hands back the epochs it missed. Call it for every
    /// envelope ``openEnvelope(_:)`` did not open, before acknowledging it.
    /// `mailboxKind`, `id` and `receivedAtMs` are the mailbox's own, and
    /// `deviceSeal` the device seal it handed over beside the envelope
    /// (`MailboxEnvelope.deviceSeal`; empty for none): one that opens for
    /// this device names the group, the sender and the epoch secret, so the
    /// envelope is handed out once this device is back in that group, or
    /// before the hold would drop it. ``HoldAnswer/full``: stop the page
    /// there, unacknowledged, take what ``nextReopenable()`` hands out
    /// through, and drain again.
    @discardableResult
    public func holdEnvelope(
        mailboxKind: UInt8, id: String, receivedAtMs: UInt64, envelope: Data,
        deviceSeal: Data = Data()
    ) throws -> HoldAnswer {
        try locked { handle in
            var held: UInt8 = 0
            try id.withCString { idPointer in
                try withBytes(envelope) { bytes, length in
                    try withBytes(deviceSeal) { seal, sealLength in
                        try check(
                            peachy_mls_hold_envelope_sealed(
                                handle, mailboxKind, idPointer, receivedAtMs, bytes, length,
                                seal, sealLength, &held
                            )
                        )
                    }
                }
            }
            return HoldAnswer(rawValue: held) ?? .notKept
        }
    }

    /// The next envelope ``holdEnvelope(mailboxKind:id:receivedAtMs:envelope:)``
    /// kept that opens now, oldest first; `nil` when none does. Take each
    /// through the same path as a fresh envelope, ``releaseHeld(id:)`` it once
    /// what was made of it is stored, and ask again until `nil`. One not
    /// released stays kept and is handed out again in the next pass or after
    /// a restart. Call it after every mailbox pass.
    public func nextReopenable() throws -> HeldEnvelope? {
        try locked { handle in
            var kind: UInt8 = 0
            var receivedAt: UInt64 = 0
            var id = PeachyMlsBuffer()
            var envelope = PeachyMlsBuffer()
            try check(peachy_mls_next_reopenable(handle, &kind, &receivedAt, &id, &envelope))
            let idBytes = takeData(&id)
            let envelopeBytes = takeData(&envelope)
            guard !idBytes.isEmpty, let idText = String(data: idBytes, encoding: .utf8) else {
                return nil
            }
            return HeldEnvelope(
                mailboxKind: kind, receivedAtMs: receivedAt, id: idText, envelope: envelopeBytes
            )
        }
    }

    /// What the envelope ``nextReopenable()`` handed out under `id` is to be
    /// made of, when it was handed out on its device seal; `nil` for one
    /// handed out on no seal, taken through as any other.
    public func heldDisposition(id: String) throws -> HeldDisposition? {
        try locked { handle in
            var fate: UInt8 = 0
            var author = PeachyMlsBuffer()
            try id.withCString { idPointer in
                try check(peachy_mls_held_disposition(handle, idPointer, &fate, &author))
            }
            let authorText = String(data: takeData(&author), encoding: .utf8) ?? ""
            let held = HeldFate(code: fate)
            if held == .ordinary && authorText.isEmpty {
                return nil
            }
            return HeldDisposition(fate: held, author: authorText.isEmpty ? nil : authorText)
        }
    }

    /// Release an envelope ``nextReopenable()`` handed out, once what was
    /// made of it is stored: it is kept no longer. True when one with that id
    /// was kept.
    @discardableResult
    public func releaseHeld(id: String) throws -> Bool {
        try locked { handle in
            var released = false
            try id.withCString { idPointer in
                try check(peachy_mls_release_held(handle, idPointer, &released))
            }
            return released
        }
    }

    /// Wrap `inner` as an envelope of `groupId`, a group this device holds.
    /// The door for every send, commit, typing frame and call signal: sealed
    /// under the epoch the inner message was made in (a typing frame or call
    /// signal: the copy's epoch), never by the group id. A message or commit
    /// made at an epoch this copy no longer keeps throws `.staleCopy`
    /// (encrypt it again and seal that); a copy no longer in the group throws
    /// `.notAMember`, and a group this device does not hold `.noSuchGroup`.
    /// A seat ask and a link preview come out keyed by the group id, as
    /// ``sealEnvelope(groupId:kind:inner:)`` seals them.
    public func sealEnvelope(groupId: Data, kind: UInt8, inner: Data) throws -> Data {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupId) { group, groupLength in
                try withBytes(inner) { bytes, length in
                    try check(
                        peachy_mls_client_seal_envelope(
                            handle, group, groupLength, kind, bytes, length, &buffer)
                    )
                }
            }
            return takeData(&buffer)
        }
    }

    /// This device's own identity.
    public func identity() throws -> Identity {
        try locked { handle in
            var actor = PeachyMlsBuffer()
            var device = PeachyMlsBuffer()
            try check(peachy_mls_client_identity(handle, &actor, &device))
            return Identity(actorId: takeString(&actor), deviceId: takeString(&device))
        }
    }

    /// The account identity key this device's own credential carries, or nil
    /// while this device holds no account certificate. Without one the client
    /// opens but cannot publish a key package or found a group.
    public func accountKey() throws -> Data? {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try check(peachy_mls_client_account_key(handle, &buffer))
            let key = takeData(&buffer)
            return key.isEmpty ? nil : key
        }
    }

    /// The actors in `groupID` whose account identity key CHANGED since this
    /// device pinned it: each one a "security code changed" notice for this
    /// conversation (docs/identity.md §Security code changed). The first
    /// key seen for an actor is pinned in silence. Call after anything that can
    /// change the tree.
    public func observeAccountKeys(groupID: Data) throws -> [String] {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_observe_account_keys(handle, bytes, length, &buffer))
            }
            return try decodeStringList(takeData(&buffer))
        }
    }

    /// Mint a key package for somebody else to add this device with.
    /// Single-use: a second add needs a second key package.
    public func generateKeyPackage() throws -> KeyPackage {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try check(peachy_mls_key_package(handle, &buffer))
            return KeyPackage(data: takeData(&buffer))
        }
    }

    /// The same key package, plus the RFC 9420 reference that names it and the
    /// ciphersuite it is for.
    ///
    /// This is what `PublishKeyPackages` wants, and ``generateKeyPackage()``
    /// is not: the directory keys each package by its `keyPackageRef`, which
    /// is the idempotency key that stops a device republishing its pool from
    /// growing it forever (docs/delivery.md §The KeyPackage
    /// lifecycle). The reference is a hash of the bare KeyPackage and NOT of
    /// the `MlsMessage` wrapper handed back beside it, so a caller computing
    /// one itself gets a plausible value no other MLS implementation agrees
    /// with. Single-use, exactly like its sibling.
    public func generateKeyPackageWithRef() throws -> PublishedKeyPackage {
        try locked { handle in
            var package = PeachyMlsBuffer()
            var reference = PeachyMlsBuffer()
            var ciphersuite: UInt16 = 0
            try check(
                peachy_mls_key_package_with_ref(handle, &package, &reference, &ciphersuite)
            )
            return PublishedKeyPackage(
                keyPackage: KeyPackage(data: takeData(&package)),
                keyPackageRef: takeData(&reference),
                ciphersuite: ciphersuite
            )
        }
    }

    /// A LAST-RESORT key package with its reference and ciphersuite: the one
    /// to publish with `lastResort` set. It carries the `last_resort`
    /// extension, so unlike its siblings it opens any number of Welcomes until
    /// it is rotated (docs/mls-core.md §Last-resort key packages).
    public func generateLastResortKeyPackageWithRef() throws -> PublishedKeyPackage {
        try locked { handle in
            var package = PeachyMlsBuffer()
            var reference = PeachyMlsBuffer()
            var ciphersuite: UInt16 = 0
            try check(
                peachy_mls_last_resort_key_package_with_ref(
                    handle, &package, &reference, &ciphersuite)
            )
            return PublishedKeyPackage(
                keyPackage: KeyPackage(data: takeData(&package)),
                keyPackageRef: takeData(&reference),
                ciphersuite: ciphersuite
            )
        }
    }

    /// Whether this device owes the directory a new last-resort key package:
    /// none minted by this build yet, or the newest is two days old.
    public func lastResortRotationDue() throws -> Bool {
        try locked { handle in
            var due = false
            try check(peachy_mls_last_resort_rotation_due(handle, &due))
            return due
        }
    }

    /// The group ids this device currently holds state for.
    ///
    /// The question it answers is "have I been here before" — a relaunched
    /// device deciding whether a conversation needs a Welcome claimed or
    /// merely a stream replayed. Local state only: a group this device has
    /// been added to but has not yet claimed the Welcome for is not in here.
    ///
    /// The order is a map's key order — unspecified, and not stable across
    /// calls. Treat it as a set.
    public func groupIDs() throws -> [Data] {
        try locked { handle in
            var count: UInt = 0
            try check(peachy_mls_group_count(handle, &count))
            var ids: [Data] = []
            ids.reserveCapacity(Int(count))
            for position in 0..<count {
                var buffer = PeachyMlsBuffer()
                try check(peachy_mls_group_id_at(handle, position, &buffer))
                ids.append(takeData(&buffer))
            }
            return ids
        }
    }

    /// Whether this device is still an active member of the group.
    ///
    /// `false` means removed, or the group left: the state is still here and
    /// still readable for history, but nothing can be sent and no commit will
    /// be accepted.
    ///
    /// A group id this device holds no state for THROWS ``MLSError``'s no-such-group
    /// case rather than answering `false`. The two are different questions —
    /// one is fixed by claiming a Welcome and the other is not — and a caller
    /// that wants them collapsed should collapse them at its own call site.
    public func isActive(groupID: Data) throws -> Bool {
        try locked { handle in
            var active = false
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_is_active(handle, bytes, length, &active))
            }
            return active
        }
    }

    /// The actor id of the member whose commit seated this device in
    /// `groupID` by a Welcome (the Welcome's verified GroupInfo signer, kept
    /// with the group's state), or `nil` for a group this device founded or
    /// joined on a build before it was kept. A Welcome from one of this
    /// account's own devices is a linked device being seated, never this
    /// person being added back (docs/account-store.md §Record values,
    /// **Leaving a group**). `nil` too for a group not held.
    public func welcomeSender(groupID: Data) throws -> String? {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_welcome_sender(handle, bytes, length, &buffer))
            }
            let actor = takeString(&buffer)
            return actor.isEmpty ? nil : actor
        }
    }

    /// The group's own name-and-photo value (`peachy_group_meta`), read out of
    /// its context, or `nil` when nobody has set one (docs/sealed-messages.md
    /// §The name is in the group). The bytes are the client format and are
    /// returned unparsed.
    public func groupMeta(groupID: Data) throws -> Data? {
        try locked { handle in
            var meta = PeachyMlsBuffer()
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_meta(handle, bytes, length, &meta))
            }
            let value = takeData(&meta)
            // A set value is never empty, so empty is absent.
            return value.isEmpty ? nil : value
        }
    }

    /// Set the group's name and photo, in ONE commit that changes
    /// `peachy_group_meta` and nothing else. Any member may.
    ///
    /// **Staged, not adopted** — see ``mergePendingCommit(groupID:)``.
    ///
    /// Throws ``MLSError/Code/extensionUnsupported`` when some member's leaf
    /// does not yet advertise the extension; that leaf's next renewal carries
    /// it.
    public func setGroupMeta(groupID: Data, value: Data) throws -> CommitBundle {
        try locked { handle in
            var commit = PeachyMlsBuffer()
            try withBytes(groupID) { bytes, length in
                try withBytes(value) { valueBytes, valueLength in
                    try check(
                        peachy_mls_group_set_meta(
                            handle, bytes, length, valueBytes, valueLength, &commit
                        )
                    )
                }
            }
            return CommitBundle(
                commit: takeData(&commit),
                welcome: nil,
                epoch: try stagedEpoch(handle, groupID)
            )
        }
    }

    /// Create a group with this device as its only member.
    public func createGroup(id groupID: Data) throws {
        try locked { handle in
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_create(handle, bytes, length))
            }
        }
    }

    /// Join a group from a Welcome. Returns the group id joined.
    public func join(welcome: Data) throws -> Data {
        try locked { handle in
            var joined = PeachyMlsBuffer()
            try withBytes(welcome) { bytes, length in
                try check(peachy_mls_group_join(handle, bytes, length, &joined))
            }
            return takeData(&joined)
        }
    }

    /// The group id of the Welcome the last ``join(welcome:)`` refused with
    /// ``MLSError/Code/alreadyAMember`` because this device already held an
    /// active group under that id, or `nil`. Two seats under one id are a
    /// contest the group's head decides (docs/delivery.md §Two seats
    /// under one group id): fetch the head for the group's handle and hand it
    /// to ``joinContestedWelcome(headEpoch:headVerifier:)``.
    public func contestedWelcomeGroupID() throws -> Data? {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try check(peachy_mls_group_contested_welcome_id(handle, &buffer))
            let id = takeData(&buffer)
            return id.isEmpty ? nil : id
        }
    }

    /// Settle the contested Welcome against the group's head (its epoch and
    /// send-key verifier). Returns the group id when the Welcome took the
    /// seat, replacing the held group; throws ``MLSError/Code/alreadyAMember``
    /// when the held group keeps it. The Welcome is gone either way.
    public func joinContestedWelcome(headEpoch: UInt64, headVerifier: Data) throws -> Data {
        try locked { handle in
            var joined = PeachyMlsBuffer()
            try withBytes(headVerifier) { bytes, length in
                try check(
                    peachy_mls_group_join_contested_welcome(handle, headEpoch, bytes, length, &joined)
                )
            }
            return takeData(&joined)
        }
    }

    /// The group a Welcome is for, and the epoch it would seat this device
    /// at, read without taking it: what
    /// ``join(welcome:headEpoch:headVerifier:)`` needs the group's head for.
    /// Both as the Welcome claims them. Writes nothing.
    public func welcomeGroup(welcome: Data) throws -> (groupID: Data, epoch: UInt64) {
        try locked { handle in
            var group = PeachyMlsBuffer()
            var epoch: UInt64 = 0
            try withBytes(welcome) { bytes, length in
                try check(peachy_mls_group_welcome_group(handle, bytes, length, &group, &epoch))
            }
            return (takeData(&group), epoch)
        }
    }

    /// Join a group from a Welcome against the group's head (its epoch and
    /// send-key verifier): the door every Welcome goes through. Above the
    /// head, or at its epoch under another send key, it throws
    /// ``MLSError/Code/alreadyAMember``; at the head it is taken and
    /// confirmed; below it, taken unconfirmed when no active copy is held.
    /// ``MLSError/Code/settleFirst`` puts the key package back: the same call
    /// succeeds once the saved commit is settled. Returns the group id joined
    /// (docs/delivery.md §Two seats under one group id).
    public func join(welcome: Data, headEpoch: UInt64, headVerifier: Data) throws -> Data {
        try locked { handle in
            var joined = PeachyMlsBuffer()
            try withBytes(welcome) { bytes, length in
                try withBytes(headVerifier) { verifier, verifierLength in
                    try check(
                        peachy_mls_group_join_at_head(
                            handle, bytes, length, headEpoch, verifier, verifierLength, &joined
                        )
                    )
                }
            }
            return takeData(&joined)
        }
    }

    /// ``join(welcome:headEpoch:headVerifier:)``, with the delivery service's
    /// verifier-log answer for the Welcome's own epoch (`FetchVerifierAt`,
    /// docs/delivery.md §FetchVerifierAt): the verifier logged
    /// there, or empty when it holds none, and `keptFrom`, the lowest epoch
    /// from which the log holds every epoch up to the head (nil when the
    /// server named none). A Welcome below the head whose send key hashes to
    /// the verifier is taken and confirmed, as one at the head is; one whose
    /// send key does not, or one at or above `keptFrom` with nothing logged,
    /// throws ``MLSError/Code/alreadyAMember``. Pass only an answer the
    /// server gave: a failed read holds the Welcome.
    public func join(
        welcome: Data, headEpoch: UInt64, headVerifier: Data, loggedVerifier: Data, keptFrom: UInt64?
    ) throws -> Data {
        try locked { handle in
            var joined = PeachyMlsBuffer()
            try withBytes(welcome) { bytes, length in
                try withBytes(headVerifier) { verifier, verifierLength in
                    try withBytes(loggedVerifier) { logged, loggedLength in
                        try check(
                            peachy_mls_group_join_at_head_logged(
                                handle, bytes, length, headEpoch, verifier, verifierLength,
                                logged, loggedLength, keptFrom ?? UInt64.max, &joined
                            )
                        )
                    }
                }
            }
            return takeData(&joined)
        }
    }

    /// Hand the group's head to the copy this device holds: a copy at the
    /// head is confirmed, and a confirmed one beside it (same epoch, another
    /// send key) lapses. An active copy no head has matched yet is confirmed
    /// by a head at any of its last 64 epochs under its send key there, and
    /// contested by one under another (the rejoin report then says
    /// contested); a head above the copy, and a head below a copy a head
    /// matched once, change nothing. Returns
    /// whether the copy is confirmed now; false for a group not held. Only a
    /// confirmed copy's epochs raise the epoch mark; no head lowers the mark or
    /// takes away the roster a copy that matched a head once names to the
    /// Welcome judge. Call it with every head read.
    @discardableResult
    public func confirmHead(groupID: Data, headEpoch: UInt64, headVerifier: Data) throws -> Bool {
        try locked { handle in
            var confirmed = false
            try withBytes(groupID) { group, groupLength in
                try withBytes(headVerifier) { verifier, verifierLength in
                    try check(
                        peachy_mls_group_confirm_head(
                            handle, group, groupLength, headEpoch, verifier, verifierLength,
                            &confirmed
                        )
                    )
                }
            }
            return confirmed
        }
    }

    /// Whether the group's head was ROLLED BACK below the copy this device
    /// holds: an active copy past `headEpoch` on which the group's own head
    /// once stood above `headEpoch`, and which held that epoch under the send
    /// key `headVerifier` names when it is one of the copy's last 64 epochs
    /// (below all of them, that the head stood above it is enough only on a
    /// copy that has kept 64 epochs since its seat, in a group no steward was
    /// ever named for on it). Such a head is no fork: keep the copy, neither
    /// forget the group nor ask back in. False for a head at or above the
    /// copy, a group not held, a head the group's own head never stood above
    /// on this copy, a verifier of any length but 32, within the last 64
    /// epochs one that differs from the copy's own there, and below them any
    /// other head. Reads only.
    public func headRolledBack(groupID: Data, headEpoch: UInt64, headVerifier: Data) throws -> Bool {
        try locked { handle in
            var rolledBack = false
            try withBytes(groupID) { group, groupLength in
                try withBytes(headVerifier) { verifier, verifierLength in
                    try check(
                        peachy_mls_group_head_rolled_back(
                            handle, group, groupLength, headEpoch, verifier, verifierLength,
                            &rolledBack
                        )
                    )
                }
            }
            return rolledBack
        }
    }

    /// When this device last finished reading the group's head, in unix
    /// milliseconds, as ``noteHeadRead(groupID:atMs:)`` recorded it; nil when
    /// it never did for this copy, or the group is not held. Kept in the
    /// group's own records and dropped with the group. Reads only.
    public func lastHeadRead(groupID: Data) throws -> Int64? {
        try locked { handle in
            var atMs: Int64 = -1
            try withBytes(groupID) { group, groupLength in
                try check(peachy_mls_group_last_head_read(handle, group, groupLength, &atMs))
            }
            return atMs < 0 ? nil : atMs
        }
    }

    /// Record that a read of the group's head finished at `atMs` (unix
    /// milliseconds), whatever it answered. Throws for a group not held.
    public func noteHeadRead(groupID: Data, atMs: Int64) throws {
        try locked { handle in
            try withBytes(groupID) { group, groupLength in
                try check(peachy_mls_group_note_head_read(handle, group, groupLength, atMs))
            }
        }
    }

    // MARK: - Group recovery

    /// What the recovery driver says to do with a copy of a group that fell
    /// behind its head or forked off it (docs/mls-core.md §Group recovery).
    /// The raw values are `peachy_mls.h`'s `PEACHY_MLS_RECOVERY_*`.
    public enum RecoveryStep: UInt32, Sendable, CaseIterable {
        /// Nothing to do.
        case inStep = 0
        /// The head is ahead: catch up from the mailbox.
        case behind = 1
        /// The server moved its head back below the copy: keep it.
        case rolledBack = 2
        /// Held for its steward: every rejoin waits.
        case held = 3
        /// Just held: fetch the missing commit, read the head at the cap.
        case holdEntered = 4
        /// Forked: forget the group and ask back in.
        case rejoinForked = 5
        /// Behind with nothing to carry it up: forget and ask back in.
        case rejoinStuck = 6
        /// Behind after a lost mailbox: forget and ask back in.
        case rejoinLost = 7
        /// A fork rejoin is due and the last was too recent: wait.
        case backoff = 8
        /// No active copy here.
        case noCopy = 9
        /// A head below the copy from an older read: read a fresh one.
        case readAgain = 10
        /// From ``MLSClient/recoveryBegin(groupID:)``: read the head.
        case readHead = 11
        /// A rejoin is due over a saved commit: settle it by the verifier
        /// logged at the copy's epoch plus one, then read the head again.
        case settleFirst = 12

        /// Whether to forget the group and ask back in.
        public var rejoins: Bool {
            self == .rejoinForked || self == .rejoinStuck || self == .rejoinLost
        }
    }

    /// Why a head was read. The raw values are `PEACHY_MLS_HEAD_READ_*`.
    public enum HeadReadKind: UInt32, Sendable {
        /// The fork check.
        case check = 0
        /// The fork check, with a message sealed past the copy known
        /// (`MLSError.Code.staleCopy`).
        case sealedAhead = 1
        /// After a lost mailbox: behind rejoins at once, nothing else is judged.
        case lost = 2
    }

    private static func recoveryStep(_ raw: UInt32) throws -> RecoveryStep {
        guard let step = RecoveryStep(rawValue: raw) else {
            throw MLSError(code: .other(-2), message: "an unknown recovery step \(raw)")
        }
        return step
    }

    /// Begin a head read of the group, before the head is fetched:
    /// ``RecoveryStep/readHead`` (fetch it, then
    /// ``recoveryJudge(groupID:kind:headEpoch:headVerifier:fresh:nowMs:)``),
    /// ``RecoveryStep/held`` or ``RecoveryStep/noCopy``.
    public func recoveryBegin(groupID: Data) throws -> RecoveryStep {
        try locked { handle in
            var step: UInt32 = 0
            try withBytes(groupID) { group, groupLength in
                try check(peachy_mls_group_recovery_begin(handle, group, groupLength, &step))
            }
            return try Self.recoveryStep(step)
        }
    }

    /// Judge a head read since ``recoveryBegin(groupID:)``. `headEpoch` nil:
    /// the server holds no head. `fresh`: the read began after the begin. On
    /// a step that ``RecoveryStep/rejoins``, read the leaves, forget the
    /// group and send them a sealed seat ask.
    public func recoveryJudge(
        groupID: Data, kind: HeadReadKind, headEpoch: UInt64?, headVerifier: Data,
        fresh: Bool, nowMs: Int64
    ) throws -> RecoveryStep {
        try locked { handle in
            var step: UInt32 = 0
            try withBytes(groupID) { group, groupLength in
                try withBytes(headVerifier) { verifier, verifierLength in
                    try check(
                        peachy_mls_group_recovery_judge(
                            handle, group, groupLength, kind.rawValue, headEpoch != nil,
                            headEpoch ?? 0, verifier, verifierLength, fresh, nowMs, &step)
                    )
                }
            }
            return try Self.recoveryStep(step)
        }
    }

    /// Whether to read the group's head over messages that would not open:
    /// at most once a minute per group, except that one sealed past the copy
    /// is let through once. True counts as that read.
    public func recoveryReadDue(groupID: Data, sealedAhead: Bool, nowMs: Int64) throws -> Bool {
        try locked { handle in
            var due = false
            try withBytes(groupID) { group, groupLength in
                try check(
                    peachy_mls_group_recovery_read_due(
                        handle, group, groupLength, sealedAhead, nowMs, &due)
                )
            }
            return due
        }
    }

    /// A mailbox drain that began at `startedAtMs` ran to the end
    /// (`evidence` false: its first page came on the stream). Answers the
    /// groups owed a second head reading now, each handed out once.
    public func recoveryDrainComplete(startedAtMs: Int64, evidence: Bool, nowMs: Int64) throws
        -> [Data]
    {
        try locked { handle in
            var owed = PeachyMlsBuffer()
            try check(
                peachy_mls_recovery_drain_complete(handle, startedAtMs, evidence, nowMs, &owed))
            return try decodeByteList(takeData(&owed))
        }
    }

    /// Add a member from their published key package.
    ///
    /// The commit goes to every existing member; the Welcome goes to the
    /// person being added, and nowhere else.
    ///
    /// **Staged, not adopted** — see ``mergePendingCommit(groupID:)``.
    public func addMember(groupID: Data, keyPackage: KeyPackage) throws -> CommitBundle {
        try locked { handle in
            var commit = PeachyMlsBuffer()
            var welcome = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try withBytes(keyPackage.data) { package, packageLength in
                    try check(
                        peachy_mls_group_add_member(
                            handle,
                            group,
                            groupLength,
                            package,
                            packageLength,
                            &commit,
                            &welcome
                        )
                    )
                }
            }
            let welcomeData = takeData(&welcome)
            return CommitBundle(
                commit: takeData(&commit),
                welcome: welcomeData.isEmpty ? nil : welcomeData,
                epoch: try stagedEpoch(handle, groupID)
            )
        }
    }

    /// Seat every device at a founding in ONE commit that names nobody
    /// (docs/delivery.md §Founding a conversation). `ownKeyPackage`
    /// is a package of THIS device, fetched like everyone else's; the Welcome
    /// seats it too. Send the Welcome to every device in `keyPackages` and to
    /// this one, and submit the commit with no recipients. ``foundingSeats``
    /// says how many devices, this one included, one founding seats.
    ///
    /// **Staged, not adopted** — see ``mergePendingCommit(groupID:)``.
    public func seatFounding(
        groupID: Data, keyPackages: [KeyPackage], ownKeyPackage: KeyPackage
    ) throws -> CommitBundle {
        try locked { handle in
            var commit = PeachyMlsBuffer()
            var welcome = PeachyMlsBuffer()
            let list = encodeByteList(keyPackages.map(\.data))
            try withBytes(groupID) { group, groupLength in
                try withBytes(list) { packages, packagesLength in
                    try withBytes(ownKeyPackage.data) { own, ownLength in
                        try check(
                            peachy_mls_group_seat_founding(
                                handle, group, groupLength, packages, packagesLength,
                                own, ownLength, &commit, &welcome
                            )
                        )
                    }
                }
            }
            let welcomeData = takeData(&welcome)
            return CommitBundle(
                commit: takeData(&commit),
                welcome: welcomeData.isEmpty ? nil : welcomeData,
                epoch: try stagedEpoch(handle, groupID)
            )
        }
    }

    /// ``addMember(groupID:keyPackage:)`` for a rejoin's seat ask whose
    /// device holds no leaf, after
    /// ``verifyJoinRequest(groupID:actorId:deviceId:proof:keyPackage:pendingActors:)``
    /// accepted it: the ask's membership is judged again, with the same
    /// `pendingActors`, on the store this add commits on, so a person the
    /// other process removed after the verdict is not put back. A refusal
    /// throws and stages nothing.
    ///
    /// **Staged, not adopted** — see ``mergePendingCommit(groupID:)``.
    public func addMemberForAsk(
        groupID: Data, keyPackage: KeyPackage, pendingActors: [String]
    ) throws -> CommitBundle {
        try locked { handle in
            var commit = PeachyMlsBuffer()
            var welcome = PeachyMlsBuffer()
            let pendingList = encodeStringList(pendingActors)
            try withBytes(groupID) { group, groupLength in
                try withBytes(keyPackage.data) { package, packageLength in
                    try withBytes(pendingList) { pending, pendingLength in
                        try check(
                            peachy_mls_group_add_member_for_ask(
                                handle,
                                group,
                                groupLength,
                                package,
                                packageLength,
                                pending,
                                pendingLength,
                                &commit,
                                &welcome
                            )
                        )
                    }
                }
            }
            let welcomeData = takeData(&welcome)
            return CommitBundle(
                commit: takeData(&commit),
                welcome: welcomeData.isEmpty ? nil : welcomeData,
                epoch: try stagedEpoch(handle, groupID)
            )
        }
    }

    /// The packages a founding leaves out: the index in `keyPackages` of each
    /// one ``seatFounding(groupID:keyPackages:ownKeyPackage:)`` would refuse,
    /// ascending. Changes nothing stored: it builds the founding commit in
    /// memory and drops it. Seat everybody else in the founding and offer
    /// those devices ordinary adds once it is merged
    /// (docs/delivery.md §Founding a conversation).
    public func foundingRefusals(groupID: Data, keyPackages: [KeyPackage]) throws -> [Int] {
        try locked { handle in
            var out = PeachyMlsBuffer()
            let list = encodeByteList(keyPackages.map(\.data))
            try withBytes(groupID) { group, groupLength in
                try withBytes(list) { packages, packagesLength in
                    try check(
                        peachy_mls_group_founding_refusals(
                            handle, group, groupLength, packages, packagesLength, &out
                        )
                    )
                }
            }
            // Four big-endian bytes an index.
            let bytes = [UInt8](takeData(&out))
            var refused: [Int] = []
            var at = 0
            while at + 4 <= bytes.count {
                var index = 0
                for byte in bytes[at..<at + 4] { index = index << 8 | Int(byte) }
                refused.append(index)
                at += 4
            }
            return refused
        }
    }

    /// Remove the member at `leafIndex`, whose leaf key is `leafKey`, both from
    /// the same ``RosterEntry`` (`roster(groupID:)`). A leaf another commit
    /// emptied and refilled since that read no longer matches, and the removal
    /// throws `noSuchMember` with nothing staged: read the roster again.
    ///
    /// **Staged, not adopted** — see ``mergePendingCommit(groupID:)``.
    public func removeMember(groupID: Data, leafIndex: UInt32, leafKey: Data) throws -> CommitBundle {
        try locked { handle in
            var commit = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try withBytes(leafKey) { key, keyLength in
                    try check(
                        peachy_mls_group_remove_member(
                            handle, group, groupLength, leafIndex, key, keyLength, &commit)
                    )
                }
            }
            return CommitBundle(
                commit: takeData(&commit),
                welcome: nil,
                epoch: try stagedEpoch(handle, groupID)
            )
        }
    }

    /// LEAVE: propose the removal of the leaf at `leafIndex`, one of this
    /// device's own person's leaves (its own included).
    ///
    /// A member cannot commit its own removal, so a person leaving proposes
    /// each of their leaves, sends each proposal to the group as an ordinary
    /// message (envelope kind 1), and another member's device commits them
    /// (``commitProposedLeaves(groupID:)``). Not a commit: nothing is staged,
    /// and the bytes returned are the message to send. Refused when
    /// `leafIndex` is another person's.
    ///
    /// The single-leaf building block. A leave that must survive a commit
    /// taking the epoch first goes through ``beginLeave(groupId:)``, which
    /// proposes every leaf at once and keeps proposing until the leave takes.
    public func proposeLeave(groupID: Data, leafIndex: UInt32) throws -> Data {
        try locked { handle in
            var proposal = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try check(
                    peachy_mls_group_propose_leave(handle, group, groupLength, leafIndex, &proposal)
                )
            }
            return takeData(&proposal)
        }
    }

    /// LEAVE UNTIL IT TAKES: propose the removal of every leaf of this
    /// device's own person and keep the group as a LEAVING stub
    /// (docs/sealed-messages.md §Leaving). Each item returned is a
    /// proposal to send to the group as an ordinary message (envelope kind 1,
    /// not urgent), addressed from ``leaveRecipients(groupId:)``: the stub has
    /// no ``roster(groupID:)`` any more.
    ///
    /// A proposal names the epoch it was made at, so a commit that lands
    /// first strands it; the stub is what lets ``followLeave(groupId:message:)``
    /// propose again at the new epoch instead of the leave silently never
    /// happening. Nothing but the leave reads the stub: ``groupIDs()``,
    /// ``isActive(groupID:)``, ``roster(groupID:)``, `encrypt` and
    /// ``processMessage(groupID:message:)`` all throw `noSuchGroup` for it.
    ///
    /// EMPTY when the group is already being left, or when nobody but this
    /// person holds a leaf, in which case the group is forgotten at once.
    public func beginLeave(groupId: Data) throws -> [Data] {
        try locked { handle in
            var proposals = PeachyMlsBuffer()
            try withBytes(groupId) { group, groupLength in
                try check(peachy_mls_group_begin_leave(handle, group, groupLength, &proposals))
            }
            return try decodeByteList(takeData(&proposals))
        }
    }

    /// Whether this device is LEAVING `groupId` (``beginLeave(groupId:)``):
    /// hand each commit entry of it to ``followLeave(groupId:message:)``,
    /// drop every other entry of it unread, and show nothing of it.
    public func isLeaving(groupId: Data) throws -> Bool {
        try locked { handle in
            var leaving = false
            try withBytes(groupId) { group, groupLength in
                try check(peachy_mls_group_is_leaving(handle, group, groupLength, &leaving))
            }
            return leaving
        }
    }

    /// Follow a group this device is LEAVING through one commit entry (raw or
    /// carried, as the commit door takes it). The items returned are the
    /// proposals to send AGAIN, as ``beginLeave(groupId:)`` returns them;
    /// EMPTY when there are none: the leave took and the group is forgotten,
    /// it was proposed at this epoch already, or the entry changed nothing.
    /// Only a store failure throws, and then the entry is held and tried again.
    public func followLeave(groupId: Data, message: Data) throws -> [Data] {
        try locked { handle in
            var proposals = PeachyMlsBuffer()
            try withBytes(groupId) { group, groupLength in
                try withBytes(message) { bytes, length in
                    try check(
                        peachy_mls_group_follow_leave(
                            handle, group, groupLength, bytes, length, &proposals
                        )
                    )
                }
            }
            return try decodeByteList(takeData(&proposals))
        }
    }

    /// Who a leave's proposals go to: one identity per identified leaf of a
    /// group this device is LEAVING, its own included, in the core's order.
    /// Throws `noSuchGroup` for a group it is not leaving, whose roster the
    /// member doors read instead.
    public func leaveRecipients(groupId: Data) throws -> [Identity] {
        try locked { handle in
            var pairs = PeachyMlsBuffer()
            try withBytes(groupId) { group, groupLength in
                try check(peachy_mls_group_leave_recipients(handle, group, groupLength, &pairs))
            }
            let flat = try decodeStringList(takeData(&pairs))
            // Pairs, actor then device: an odd count is a door that wrote half
            // a pair, and addressing from it would drop a device silently.
            guard flat.count % 2 == 0 else {
                throw MLSError(code: .codec, message: "malformed leave recipients: an odd count")
            }
            return stride(from: 0, to: flat.count, by: 2).map { at in
                Identity(actorId: flat[at], deviceId: flat[at + 1])
            }
        }
    }

    /// Commit the LEAVES this device holds: one commit naming every leave
    /// queued through the message door that is not this device's own
    /// person's. `nil` when there is none, and then nothing is staged.
    ///
    /// **Staged, not adopted** — see ``mergePendingCommit(groupID:)``.
    public func commitProposedLeaves(groupID: Data) throws -> CommitBundle? {
        try locked { handle in
            var commit = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try check(
                    peachy_mls_group_commit_proposed_leaves(handle, group, groupLength, &commit)
                )
            }
            let bytes = takeData(&commit)
            if bytes.isEmpty { return nil }
            return CommitBundle(
                commit: bytes,
                welcome: nil,
                epoch: try stagedEpoch(handle, groupID)
            )
        }
    }

    /// Replace the leaf at `leafIndex` with a fresh key package, in ONE commit.
    ///
    /// THE REJOIN, seen from a member that is still awake
    /// (docs/delivery.md §The client contract on `behind_retention`).
    /// A device that slept past the delivery service's retention window can
    /// neither catch up nor act in the group; some member who IS current
    /// removes its stale leaf and adds it back from a fresh key package, and
    /// the Welcome in the returned bundle is what the returning device joins
    /// on. `welcome` is never nil for a replace that succeeded.
    ///
    /// One commit and not two, because two would put the group through an
    /// epoch the person is not in: every other roster flickers, anything said
    /// in that window is unreadable to them forever, and a concurrent
    /// committer can wedge itself between the halves.
    ///
    /// Throws before anything is built when the key package belongs to a
    /// different actor than the leaf it would replace, when `leafIndex` is this
    /// device's own leaf, or when nobody occupies it.
    ///
    /// **Staged, not adopted** — see ``mergePendingCommit(groupID:)``.
    public func replaceMember(
        groupID: Data,
        leafIndex: UInt32,
        keyPackage: KeyPackage
    ) throws -> CommitBundle {
        try locked { handle in
            var commit = PeachyMlsBuffer()
            var welcome = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try withBytes(keyPackage.data) { package, packageLength in
                    try check(
                        peachy_mls_group_replace_member(
                            handle,
                            group,
                            groupLength,
                            leafIndex,
                            package,
                            packageLength,
                            &commit,
                            &welcome
                        )
                    )
                }
            }
            let welcomeData = takeData(&welcome)
            return CommitBundle(
                commit: takeData(&commit),
                welcome: welcomeData.isEmpty ? nil : welcomeData,
                epoch: try stagedEpoch(handle, groupID)
            )
        }
    }

    /// Reseat a person whose every device is gone: remove `leafIndexes`,
    /// which must be every leaf of one person, and add `keyPackage`, a new
    /// device of that same person carrying an account's signature, in ONE
    /// commit. The one way a person's last leaf leaves without the account's
    /// signed revocation or a credential past its grace; a new account key
    /// shows every member that person's security code changing
    /// (docs/identity.md §Revocation reaches a seated leaf through
    /// the roster).
    ///
    /// **Staged, not adopted** — see ``mergePendingCommit(groupID:)``.
    public func reseatPerson(
        groupID: Data,
        leafIndexes: [UInt32],
        keyPackage: KeyPackage
    ) throws -> CommitBundle {
        try locked { handle in
            var commit = PeachyMlsBuffer()
            var welcome = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try withBytes(keyPackage.data) { package, packageLength in
                    try leafIndexes.withUnsafeBufferPointer { leaves in
                        try check(
                            peachy_mls_group_reseat_person(
                                handle,
                                group,
                                groupLength,
                                leaves.baseAddress,
                                UInt(leaves.count),
                                package,
                                packageLength,
                                &commit,
                                &welcome
                            )
                        )
                    }
                }
            }
            let welcomeData = takeData(&welcome)
            return CommitBundle(
                commit: takeData(&commit),
                welcome: welcomeData.isEmpty ? nil : welcomeData,
                epoch: try stagedEpoch(handle, groupID)
            )
        }
    }

    /// Rotate this device's leaf key and commit it.
    ///
    /// **Staged, not adopted** — see ``mergePendingCommit(groupID:)``.
    public func selfUpdate(groupID: Data) throws -> CommitBundle {
        try locked { handle in
            var commit = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try check(peachy_mls_group_self_update(handle, group, groupLength, &commit))
            }
            return CommitBundle(
                commit: takeData(&commit),
                welcome: nil,
                epoch: try stagedEpoch(handle, groupID)
            )
        }
    }

    /// Hand this client a fresh device credential (the token `RegisterDevice`
    /// just returned) for the SAME seat and signing key. Commits nothing; it
    /// is what ``refreshCredential(groupID:)`` will carry. Throws a policy
    /// error for a credential naming another actor, device or key, and an
    /// invalid-argument one for a credential no fresher than the one held.
    /// docs/identity.md §Refreshing a seated leaf.
    ///
    /// `ownAccountIdentity`, named at every call: the account identity key
    /// this device derives from the account key it holds (read where the app
    /// keeps it, or just arrived with the certificate), or `nil` only for a
    /// device that holds none yet, which keeps the one the client was opened
    /// with. A credential certified under any other key throws
    /// `.credentialRejected` (`notOwnAccountKey`) and the client keeps what it
    /// had.
    public func updateCredential(_ credential: Data, ownAccountIdentity: Data?) throws {
        try locked { handle in
            try withBytes(credential) { bytes, length in
                try withOptionalBytes(ownAccountIdentity) { ownBytes, ownLength in
                    try check(
                        peachy_mls_client_update_credential(handle, bytes, length, ownBytes, ownLength))
                }
            }
        }
    }

    /// Unix seconds at which this device's leaf credential in the group lapses.
    public func ownLeafCredentialExpiresAt(groupID: Data) throws -> Int64 {
        try locked { handle in
            var expiresAt: Int64 = 0
            try withBytes(groupID) { group, groupLength in
                try check(
                    peachy_mls_group_own_leaf_credential_expires_at(
                        handle, group, groupLength, &expiresAt
                    )
                )
            }
            return expiresAt
        }
    }

    /// Whether this device's leaf is inside the refresh window (or lapsed),
    /// whatever credential the client holds. True while
    /// ``credentialRefreshDue(groupID:)`` is false means: fetch today's
    /// credential and ``updateCredential(_:ownAccountIdentity:)`` first.
    public func leafCredentialExpiring(groupID: Data) throws -> Bool {
        try locked { handle in
            var expiring = false
            try withBytes(groupID) { group, groupLength in
                try check(
                    peachy_mls_group_leaf_credential_expiring(handle, group, groupLength, &expiring)
                )
            }
            return expiring
        }
    }

    /// Whether this device's leaf lapsed longer ago than the grace every member
    /// allows, so nothing it sends is accepted any more. True means: stop
    /// claiming a seal and ask for a seat; never build a renewal.
    public func leafCredentialPastGrace(groupID: Data) throws -> Bool {
        try locked { handle in
            var past = false
            try withBytes(groupID) { group, groupLength in
                try check(
                    peachy_mls_group_leaf_credential_past_grace(handle, group, groupLength, &past)
                )
            }
            return past
        }
    }

    /// Whether a renewal commit should be built now: the leaf is expiring,
    /// nothing is staged, and the client holds a fresher credential.
    public func credentialRefreshDue(groupID: Data) throws -> Bool {
        try locked { handle in
            var due = false
            try withBytes(groupID) { group, groupLength in
                try check(
                    peachy_mls_group_credential_refresh_due(handle, group, groupLength, &due)
                )
            }
            return due
        }
    }

    /// Commit a self-update whose leaf carries this client's current
    /// credential. **Staged, not adopted**, exactly like
    /// ``selfUpdate(groupID:)``; a renewal never carries a Welcome.
    public func refreshCredential(groupID: Data) throws -> CommitBundle {
        try locked { handle in
            var commit = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try check(peachy_mls_group_refresh_credential(handle, group, groupLength, &commit))
            }
            return CommitBundle(
                commit: takeData(&commit),
                welcome: nil,
                epoch: try stagedEpoch(handle, groupID)
            )
        }
    }

    /// The delivery service TOOK the staged commit: adopt the new epoch, and
    /// return it.
    ///
    /// ``addMember(groupID:keyPackage:)``, ``removeMember(groupID:leafIndex:leafKey:)``
    /// and ``selfUpdate(groupID:)`` stage a commit and stop. Until one of this
    /// and ``clearPendingCommit(groupID:)`` is called, the group is still at its
    /// old epoch with its old keys, and it will refuse both to build a second
    /// commit and to process an incoming one.
    ///
    /// ```swift
    /// let bundle = try client.addMember(groupID: id, keyPackage: package)
    /// do {
    ///     try await ds.submitCommit(for: id, bundle)  // SubmitCommit: handle, wrapped commit (docs/delivery.md §SubmitCommit)
    /// } catch DeliveryError.failedPrecondition {
    ///     try client.clearPendingCommit(groupID: id)  // this branch never happened
    ///     throw ...                                   // then replay the server's order
    /// }
    /// try client.mergePendingCommit(groupID: id)
    /// ```
    ///
    /// Merging before the server has agreed puts this device on a branch the
    /// group never took: its epoch secrets came from a commit no other member
    /// will apply, nothing throws, ``isActive(groupID:)`` stays true, and every
    /// message it sends afterward is unreadable to everybody. The delivery
    /// service's refusal IS the total order
    /// (`docs/delivery.md` §The ordering rule), so losing that race
    /// is ordinary traffic and not an exceptional case.
    ///
    /// - Throws: ``MLSError`` with `.invalidArgument` if nothing is staged. A
    ///   caller that has lost track of its own state should hear about it: the
    ///   epoch it would go on to report is one it never earned.
    @discardableResult
    public func mergePendingCommit(groupID: Data) throws -> UInt64 {
        try locked { handle in
            var epoch: UInt64 = 0
            try withBytes(groupID) { group, groupLength in
                try check(
                    peachy_mls_group_merge_pending_commit(handle, group, groupLength, &epoch)
                )
            }
            return epoch
        }
    }

    /// The delivery service REFUSED the staged commit: drop the branch.
    ///
    /// Safe to call with nothing staged, unlike
    /// ``mergePendingCommit(groupID:)`` — this is the error path, and an error
    /// path that fails for being taken twice is one callers get wrong. After
    /// it, the group sits exactly where the server left it and the caller
    /// replays the server's commits with ``processCommit(groupID:message:)``.
    public func clearPendingCommit(groupID: Data) throws {
        try locked { handle in
            try withBytes(groupID) { group, groupLength in
                try check(peachy_mls_group_clear_pending_commit(handle, group, groupLength))
            }
        }
    }

    /// Whether this group is holding a staged commit awaiting a verdict.
    public func hasPendingCommit(groupID: Data) throws -> Bool {
        try locked { handle in
            var pending = false
            try withBytes(groupID) { group, groupLength in
                try check(
                    peachy_mls_group_has_pending_commit(handle, group, groupLength, &pending)
                )
            }
            return pending
        }
    }

    /// What ``settleSavedCommit(groupID:headEpoch:headVerifier:)`` did with a
    /// commit found staged when the client opened.
    public enum SavedCommit: Sendable, Equatable {
        /// The head was the commit's: merged.
        case merged
        /// The head was not the commit's: cleared.
        case cleared
        /// The head is past the commit's epoch: kept, for its own echo or
        /// another member's commit at its epoch to decide.
        case waiting
    }

    /// Whether this group holds a commit found staged when this client
    /// opened, whose verdict this device never heard (docs/mls-core.md
    /// §A commit saved across a restart). The app that owns the store settles
    /// it with ``settleSavedCommit(groupID:headEpoch:headVerifier:)`` before
    /// it processes anything for the group.
    public func hasSavedCommit(groupID: Data) throws -> Bool {
        try locked { handle in
            var saved = false
            try withBytes(groupID) { group, groupLength in
                try check(
                    peachy_mls_group_has_saved_commit(handle, group, groupLength, &saved)
                )
            }
            return saved
        }
    }

    /// Settle a saved commit against the group's head (its epoch and send-key
    /// verifier): merged when the head is the commit's, cleared when it is
    /// not, kept when the head is past the commit's epoch. A caller that
    /// cannot read the head calls nothing.
    public func settleSavedCommit(groupID: Data, headEpoch: UInt64, headVerifier: Data) throws
        -> SavedCommit
    {
        try locked { handle in
            var verdict: UInt32 = 0
            try withBytes(groupID) { group, groupLength in
                try withBytes(headVerifier) { verifier, verifierLength in
                    try check(
                        peachy_mls_group_settle_saved_commit(
                            handle, group, groupLength, headEpoch, verifier, verifierLength,
                            &verdict)
                    )
                }
            }
            // `peachy_mls.h`'s `PEACHY_MLS_SAVED_COMMIT_*`.
            switch verdict {
            case 1: return .merged
            case 2: return .cleared
            default: return .waiting
            }
        }
    }

    /// The group's roster, including any leaf whose credential does not
    /// currently verify — see `RosterEntry`.
    public func roster(groupID: Data) throws -> [RosterEntry] {
        try locked { handle in
            var count: UInt = 0
            try withBytes(groupID) { group, groupLength in
                try check(peachy_mls_group_member_count(handle, group, groupLength, &count))
            }

            var entries: [RosterEntry] = []
            entries.reserveCapacity(Int(count))
            for position in 0..<count {
                var leafIndex: UInt32 = 0
                var actor = PeachyMlsBuffer()
                var device = PeachyMlsBuffer()
                var deviceKey = PeachyMlsBuffer()
                var treeKey = PeachyMlsBuffer()
                var rejection: UInt32 = 0
                try withBytes(groupID) { group, groupLength in
                    try check(
                        peachy_mls_group_member(
                            handle,
                            group,
                            groupLength,
                            position,
                            &leafIndex,
                            &actor,
                            &device,
                            &deviceKey,
                            &treeKey,
                            &rejection
                        )
                    )
                }
                let leafTreeKey = takeData(&treeKey)
                let identity = Identity(
                    actorId: takeString(&actor),
                    deviceId: takeString(&device)
                )
                // Taken unconditionally, even for a leaf that did not verify:
                // the ABI hands back an EMPTY buffer there, and a buffer that
                // is never taken is a buffer that is never freed.
                let leafKey = takeData(&deviceKey)
                var accountKey = PeachyMlsBuffer()
                try withBytes(groupID) { group, groupLength in
                    try check(
                        peachy_mls_group_member_account_key(
                            handle, group, groupLength, position, &accountKey)
                    )
                }
                let leafAccountKey = takeData(&accountKey)

                entries.append(
                    RosterEntry(
                        leafIndex: leafIndex,
                        identity: rejection == 0
                            ? .success(identity)
                            // A code this build does not know is still a
                            // rejection: reporting it as `.malformed` would be
                            // a guess, so an unmapped number becomes the one
                            // thing that is certainly true — the leaf did not
                            // verify — under `.malformed` only as a last
                            // resort.
                            : .failure(CredentialRejection(rawValue: rejection) ?? .malformed),
                        deviceKey: leafKey,
                        accountKey: leafAccountKey,
                        leafKey: leafTreeKey
                    )
                )
            }
            return entries
        }
    }

    /// The identity INSIDE a raw key package, read out of the bytes rather
    /// than taken from whoever handed them over.
    ///
    /// Taking the device id or key from the server instead would let it answer
    /// with a truthful pair and a key package carrying a DIFFERENT key.
    /// ``KeyPackageIdentity/deviceKey`` is that key, straight out of the
    /// package. Seating a device of this device's OWN account goes through
    /// ``checkOwnDeviceApproval(keyPackage:approverDeviceId:approvalSignature:)``,
    /// which reads the package the same way and checks the device's approval
    /// against keys this device already trusts
    /// (docs/identity.md §What the adder checks).
    ///
    /// A well-formed package whose credential does not verify comes back with
    /// a `.failure` identity — a verdict, not a thrown error, exactly as on the
    /// roster. It THROWS only when the bytes are not a key package this build
    /// accepts at all, which is a different answer. The accepted encoding is
    /// ``addMember(groupID:keyPackage:)``'s.
    public func keyPackageIdentity(_ keyPackage: Data) throws -> KeyPackageIdentity {
        try locked { handle in
            var actor = PeachyMlsBuffer()
            var device = PeachyMlsBuffer()
            var key = PeachyMlsBuffer()
            var rejection: UInt32 = 0
            try withBytes(keyPackage) { bytes, length in
                try check(
                    peachy_mls_key_package_identity(
                        handle,
                        bytes,
                        length,
                        &actor,
                        &device,
                        &key,
                        &rejection
                    )
                )
            }
            let identity = Identity(
                actorId: takeString(&actor),
                deviceId: takeString(&device)
            )
            return KeyPackageIdentity(
                identity: rejection == 0
                    ? .success(identity)
                    // A code this build does not know is still a rejection:
                    // reporting it as `.malformed` is a last resort rather than
                    // a guess at which of the eight it was.
                    : .failure(CredentialRejection(rawValue: rejection) ?? .malformed),
                deviceKey: takeData(&key)
            )
        }
    }

    /// The ACCOUNT identity key inside a raw key package (32 bytes), read out
    /// of its own verified credential; empty when the credential does not
    /// verify or carries no certificate. What an adder compares with a
    /// security code this device verified before it seats somebody else's
    /// device (docs/identity.md §Verified). Throws as
    /// ``keyPackageIdentity(_:)`` does.
    public func keyPackageAccountKey(_ keyPackage: Data) throws -> Data {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(keyPackage) { bytes, length in
                try check(peachy_mls_key_package_account_key(handle, bytes, length, &buffer))
            }
            return takeData(&buffer)
        }
    }

    /// Whether this device may seat `keyPackage`, a device of its OWN account,
    /// given the approval the device list carries for it (`approverDeviceId`
    /// and `approvalSignature`, both empty for none).
    ///
    /// A certificate alone does not decide who joins. The core checks the
    /// approval only against keys this device already trusts: its own, the
    /// device that let it in (``rememberOwnApprover(deviceId:signingKey:)``),
    /// and the devices whose approvals it verified under one of those
    /// (docs/identity.md §What the adder checks). Only
    /// ``OwnDeviceVerdict/seats`` verdicts may seat the device. Throws only
    /// for a caller bug or a closed client, never for
    /// a refusal.
    public func checkOwnDeviceApproval(
        keyPackage: Data,
        approverDeviceId: String,
        approvalSignature: Data
    ) throws -> OwnDeviceVerdict {
        try locked { handle in
            var verdict: UInt32 = UInt32.max
            try approverDeviceId.withCString { approver in
                try withBytes(keyPackage) { package, packageLength in
                    try withBytes(approvalSignature) { signature, signatureLength in
                        try check(
                            peachy_mls_check_own_device_approval(
                                handle,
                                package,
                                packageLength,
                                approver,
                                signature,
                                signatureLength,
                                &verdict
                            )
                        )
                    }
                }
            }
            // A code this build does not know seats nobody.
            return OwnDeviceVerdict(rawValue: verdict) ?? .credentialRejected
        }
    }

    /// May this device hand its account's history to `deviceId`, a row of its
    /// own account's device list? The verdict
    /// ``checkOwnDeviceApproval(keyPackage:approverDeviceId:approvalSignature:)``
    /// gives, read from the row: `deviceKey` is the row's signing key, and
    /// `approverDeviceId` and `approvalSignature` its `approvedByDeviceID` and
    /// `approvalSignature`, both empty for none.
    ///
    /// Only ``OwnDeviceVerdict/seats`` verdicts get the hand-off; any other
    /// gets the nothing-to-send note (docs/sealed-messages.md
    /// §Handing history to your own new device). A removed device keeps the
    /// account key, so the list's `accountCertified` says nothing about who
    /// holds a row. Reads only. Throws only for a caller bug or a closed
    /// client, never for a refusal.
    public func checkOwnDeviceKey(
        deviceId: String,
        deviceKey: Data,
        approverDeviceId: String,
        approvalSignature: Data
    ) throws -> OwnDeviceVerdict {
        try locked { handle in
            var verdict: UInt32 = UInt32.max
            try deviceId.withCString { device in
                try approverDeviceId.withCString { approver in
                    try withBytes(deviceKey) { key, keyLength in
                        try withBytes(approvalSignature) { signature, signatureLength in
                            try check(
                                peachy_mls_check_own_device_key(
                                    handle,
                                    device,
                                    key,
                                    keyLength,
                                    approver,
                                    signature,
                                    signatureLength,
                                    &verdict
                                )
                            )
                        }
                    }
                }
            }
            // A code this build does not know hands nothing over.
            return OwnDeviceVerdict(rawValue: verdict) ?? .credentialRejected
        }
    }

    /// Remember the device that let this one in (its id and 32-byte signing
    /// key, as the approval named it), so this device trusts it before the two
    /// share a group. Called once, right after
    /// ``accountKeyAcceptHybrid(recipientSeed:approverSigningKey:deviceId:box:linkKeySeed:confirmedApproverKey:serverApprovalAllowed:)``
    /// succeeds.
    public func rememberOwnApprover(deviceId: String, signingKey: Data) throws {
        try locked { handle in
            try deviceId.withCString { device in
                try withBytes(signingKey) { key, keyLength in
                    try check(peachy_mls_remember_own_approver(handle, device, key, keyLength))
                }
            }
        }
    }

    /// Forget `deviceId`, a device of this account that the account removed
    /// (this device's own `RevokeDevice`, or a revoked row on the device
    /// list): no longer trusted as the device that let this one in, its
    /// leaves no longer known, its approvals vouch for nobody, and
    /// ``checkOwnDeviceApproval(keyPackage:approverDeviceId:approvalSignature:)``
    /// never seats it again. Idempotent; answers whether it was not forgotten
    /// already. Throws for this device's own id.
    ///
    /// `signingKey` is the removed device's 32-byte signing key as its
    /// device-list row carries it, nil when no row is known.
    @discardableResult
    public func forgetOwnDevice(deviceId: String, signingKey: Data? = nil) throws -> Bool {
        try locked { handle in
            try deviceId.withCString { device in
                try withOptionalBytes(signingKey) { key, keyLength in
                    var fresh = false
                    try check(peachy_mls_forget_own_device(handle, device, key, keyLength, &fresh))
                    return fresh
                }
            }
        }
    }

    /// Whether the leaf at `leafIndex` of `groupID`, which the delivery service
    /// or this account's device list named as revoked, may be removed: its own
    /// account signed `revocation` (empty for none) over its key, or its
    /// credential has lapsed on both this device's clock and the group's tree
    /// clock (with the person keeping a live leaf there, or past the grace), or
    /// (until signed revocations are enforced) its person keeps another leaf in
    /// the group. A person's last leaf never goes on the server's word alone
    /// (docs/identity.md §Revocation reaches a seated leaf through the
    /// roster).
    ///
    /// A revocation that verifies is kept, with `revokedAt`: the second the
    /// delivery service says it took effect (Unix seconds, `0` when it did not
    /// say). From then on this device refuses that key's messages received at
    /// or after it, in every group, and reads those received before it
    /// (``processMessage(groupID:message:receivedAt:)``).
    public func staleLeafRemovable(
        groupID: Data, leafIndex: UInt32, revocation: Data, revokedAt: Int64 = 0
    ) throws -> Bool {
        try locked { handle in
            var removable = false
            try withBytes(groupID) { group, groupLength in
                try withBytes(revocation) { signature, signatureLength in
                    try check(
                        peachy_mls_stale_leaf_removable(
                            handle, group, groupLength, leafIndex, signature, signatureLength,
                            revokedAt, &removable)
                    )
                }
            }
            return removable
        }
    }

    /// THE DOOR FOR A LEAF THE SERVER NAMED (`stale_device_ids`,
    /// `retired_device_ids`): judge it as
    /// ``staleLeafRemovable(groupID:leafIndex:revocation:revokedAt:)`` does
    /// and, only where that allows, stage its removal as
    /// ``removeMember(groupID:leafIndex:leafKey:)`` does, with the same
    /// `leafKey` check (`peachy_mls_group_remove_stale_leaf`). Nil, with
    /// nothing staged, when the leaf stays: a person's last leaf on the
    /// server's word alone, a leaf whose credential does not verify, or this
    /// device's own leaf.
    ///
    /// ``removeMember(groupID:leafIndex:leafKey:)`` does not ask the judge,
    /// and receivers do not re-judge a removal: a removal acting on a list the
    /// server handed over goes through this door, never the plain one.
    ///
    /// **Staged, not adopted** — see ``mergePendingCommit(groupID:)``.
    public func removeStaleLeaf(
        groupID: Data, leafIndex: UInt32, leafKey: Data, revocation: Data, revokedAt: Int64 = 0
    ) throws -> CommitBundle? {
        try locked { handle in
            var staged = false
            var commit = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try withBytes(leafKey) { key, keyLength in
                    try withBytes(revocation) { signature, signatureLength in
                        try check(
                            peachy_mls_group_remove_stale_leaf(
                                handle, group, groupLength, leafIndex, key, keyLength, signature,
                                signatureLength, revokedAt, &staged, &commit)
                        )
                    }
                }
            }
            let bytes = takeData(&commit)
            guard staged else { return nil }
            return CommitBundle(
                commit: bytes,
                welcome: nil,
                epoch: try stagedEpoch(handle, groupID)
            )
        }
    }

    /// Pin the links this account's device list states: `rowsJSON` is a JSON
    /// array of `{"id","twinOf"}` (any other field ignored), and the first
    /// `twinOf` this device sees for an id is the one it keeps. Called on
    /// every read of the device list; answers how many it pinned now.
    @discardableResult
    public func noteOwnInstallLinks(_ rowsJSON: String) throws -> UInt32 {
        try locked { handle in
            var pinned: UInt32 = 0
            try rowsJSON.withCString { text in
                try check(peachy_mls_note_own_install_links(handle, text, &pinned))
            }
            return pinned
        }
    }

    /// The account's revocations of the rows a removal signs, made with
    /// `accountKey`: only rows whose keys this device vouches for on its own
    /// approval chain, a linked row only when the confirmation named it
    /// (`namedWith`) and on the link it pinned, nothing for a denial, and
    /// nothing that touches this install. `requestJSON` is
    /// `{"named","denying","namedWith","ownDeviceIds","rows","restoredSince"}`
    /// (the last, Unix seconds, for the rows a PIN restore signed out, only
    /// keys the restoring registration's answer kept,
    /// ``noteRestoreSignedOut(_:)``, and none before), each row
    /// `{"id","twinOf","signingKey","approvedByDeviceId","approvalSignature",
    /// "revoked","revokedAt"}`,
    /// bytes as hex; answers `[{"deviceId","signature"}]`, the signature as hex
    /// (docs/identity.md §RevokeDevice).
    public func signInstallRevocations(accountKey: Data, requestJSON: String) throws -> String {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(accountKey) { key, keyLength in
                try requestJSON.withCString { text in
                    try check(
                        peachy_mls_sign_install_revocations(handle, key, keyLength, text, &buffer))
                }
            }
            return takeString(&buffer)
        }
    }

    /// Keep what the registration that restored this device from its PIN
    /// answered as signed out: `requestJSON` is
    /// `{"restoredSince","keys","certificates","accountIdentityKey"}`, bytes as
    /// hex, the identity key derived from the account key this device holds:
    /// a key is kept only when its certificate verifies under the identity
    /// key the client holds (a request naming another is refused), or under
    /// the request's while it holds none, and only when nothing is kept for
    /// that restore yet; a kept
    /// key is never approved here again. Answers how many keys it kept now
    /// (docs/identity.md §RevokeDevice).
    @discardableResult
    public func noteRestoreSignedOut(_ requestJSON: String) throws -> UInt32 {
        try locked { handle in
            var kept: UInt32 = 0
            try requestJSON.withCString { text in
                try check(peachy_mls_note_restore_signed_out(handle, text, &kept))
            }
            return kept
        }
    }

    /// This device's approval of `deviceId` holding `signingKey`, signed with
    /// this device's own key: the 64 bytes
    /// ``signDeviceApproval(seed:deviceId:signingKey:)`` makes from its seed.
    /// Throws for a key this device forgot, signed the account's revocation
    /// of, or took from a restore's answer as signed out: that device starts
    /// over under a new key. With `restoredSince` above zero (this device's
    /// PIN restore, Unix seconds) it closes that restore when no answer is
    /// kept for it yet.
    public func signOwnDeviceApproval(deviceId: String, signingKey: Data, restoredSince: Int64)
        throws -> Data
    {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try deviceId.withCString { id in
                try withBytes(signingKey) { key, keyLength in
                    try check(
                        peachy_mls_sign_own_device_approval(
                            handle, id, key, keyLength, restoredSince, &buffer))
                }
            }
            return takeData(&buffer)
        }
    }

    /// The device ids of this account's OTHER devices that are leaves of a
    /// group this device is active in, each once: what this device has seen of
    /// its own account, from commits it verified. The "new device linked"
    /// notice is keyed on it. A leaf under a key its id was not first seen
    /// with comes back as `<device id>#<device key, 64 hex>`.
    public func ownSiblingLeaves() throws -> [String] {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try check(peachy_mls_own_sibling_leaves(handle, &buffer))
            return try decodeStringList(takeData(&buffer))
        }
    }

    // MARK: - A call link's client

    /// This client's own-device trust, as JSON: its identity, its approval
    /// chain, and every device id and key this account forgot. Handed to
    /// ``adoptOwnDeviceTrust(_:)`` of a call link's client on the same device
    /// (docs/calls.md §Call links on participant keys); it never
    /// leaves the device. Reads only.
    public func ownDeviceTrust() throws -> String {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try check(peachy_mls_own_device_trust(handle, &buffer))
            return takeString(&buffer)
        }
    }

    /// Adopt `trust`, the ``ownDeviceTrust()`` of this device's main client,
    /// into this (call link) client: its adds then refuse a forgotten device
    /// of the account, a Welcome signed by one seats it in nothing, and its
    /// own-device checks run on the main client's chain. Throws unless the
    /// form is this very device's; nothing is adopted unless all of it reads.
    /// Forgotten ids and keys accumulate across adoptions.
    public func adoptOwnDeviceTrust(_ trust: String) throws {
        try locked { handle in
            try trust.withCString { text in
                try check(peachy_mls_adopt_own_device_trust(handle, text))
            }
        }
    }

    /// Grow the refusals this client enforces by `names`, the refusals the
    /// delivery service switched on as the app holds them
    /// (docs/delivery.md §The protocol floor). Hand them in after
    /// every open and whenever the app's list grows. Never shrinks; a name
    /// this build does not know is ignored. In memory.
    public func adoptClientRefusals(_ names: [String]) throws {
        try locked { handle in
            try names.joined(separator: ",").withCString { text in
                try check(peachy_mls_client_adopt_refusals(handle, text))
            }
        }
    }

    /// What this client makes of a leaf `(actorId, deviceId, deviceKey)` in
    /// one of its groups. Only ``OwnDeviceStanding/thisDevice`` and
    /// ``OwnDeviceStanding/onChain`` count as the person's own device; a
    /// failure answers ``OwnDeviceStanding/offChain``.
    public func ownDeviceStanding(actorId: String, deviceId: String, deviceKey: Data) -> OwnDeviceStanding {
        let code: UInt32? = try? locked { handle in
            try actorId.withCString { actor in
                try deviceId.withCString { device in
                    try withBytes(deviceKey) { key, keyLength in
                        var standing = OwnDeviceStanding.offChain.rawValue
                        try check(peachy_mls_own_device_standing(
                            handle, actor, device, key, keyLength, &standing))
                        return standing
                    }
                }
            }
        }
        // A code this build does not know is not the person's.
        return code.flatMap(OwnDeviceStanding.init(rawValue:)) ?? .offChain
    }

    /// Sign a request to be seated in `groupID` as this device, now: the
    /// 89-byte proof (`mls/core/src/join_request.rs`) that travels beside a
    /// seat ask's `{actor, device}` claim. Every seat ask carries one.
    public func signJoinRequest(groupID: Data) throws -> Data {
        try locked { handle in
            var proof = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try check(peachy_mls_sign_join_request(handle, group, groupLength, &proof))
            }
            return takeData(&proof)
        }
    }

    /// Whether `(actorId, deviceId)`'s signed request to be seated in
    /// `groupID` holds, checked against `keyPackage`: the package fetched to
    /// seat that device. Only ``JoinRequestVerdict/accepted`` may seat
    /// anybody. Throws only for a caller bug (a string the C door cannot
    /// carry), never for a refusal.
    ///
    /// `pendingActors` names the people the caller is itself still trying to
    /// add, from its own invitations and never from the ask: besides current
    /// members and this device's own person, the only askers who can be
    /// accepted. Anybody else is ``JoinRequestVerdict/notAMember``: a signed
    /// ask proves who is asking, never that they belong. So is a person whose
    /// last leaf this device saw leave the group, even when `pendingActors`
    /// names them; a person the caller admits by its own rule goes through
    /// ``verifyAdmittedJoinRequest(groupID:actorId:deviceId:proof:keyPackage:)``.
    public func verifyJoinRequest(
        groupID: Data,
        actorId: String,
        deviceId: String,
        proof: Data,
        keyPackage: Data,
        pendingActors: [String]
    ) throws -> JoinRequestVerdict {
        try locked { handle in
            var verdict: UInt32 = UInt32.max
            let pendingList = encodeStringList(pendingActors)
            try actorId.withCString { actor in
                try deviceId.withCString { device in
                    try withBytes(pendingList) { pending, pendingLength in
                        try withBytes(groupID) { group, groupLength in
                            try withBytes(proof) { proofBytes, proofLength in
                                try withBytes(keyPackage) { package, packageLength in
                                    try check(
                                        peachy_mls_verify_join_request(
                                            handle,
                                            group,
                                            groupLength,
                                            actor,
                                            device,
                                            proofBytes,
                                            proofLength,
                                            package,
                                            packageLength,
                                            pending,
                                            pendingLength,
                                            &verdict
                                        )
                                    )
                                }
                            }
                        }
                    }
                }
            }
            // A code this build does not know seats nobody.
            return JoinRequestVerdict(rawValue: verdict) ?? .malformed
        }
    }

    /// ``verifyJoinRequest(groupID:actorId:deviceId:proof:keyPackage:pendingActors:)``
    /// for a person this device has itself decided to admit by its own rule:
    /// somebody who asked through a group link it approved, or through an
    /// open group's join inbox. Every check but membership, which the
    /// caller's rule already decided; a person who left the group may come
    /// back this way. Never for a rejoin's seat ask (envelope kind 3). Throws
    /// only for a caller bug, never for a refusal.
    public func verifyAdmittedJoinRequest(
        groupID: Data,
        actorId: String,
        deviceId: String,
        proof: Data,
        keyPackage: Data
    ) throws -> JoinRequestVerdict {
        try locked { handle in
            var verdict: UInt32 = UInt32.max
            try actorId.withCString { actor in
                try deviceId.withCString { device in
                    try withBytes(groupID) { group, groupLength in
                        try withBytes(proof) { proofBytes, proofLength in
                            try withBytes(keyPackage) { package, packageLength in
                                try check(
                                    peachy_mls_verify_admitted_join_request(
                                        handle,
                                        group,
                                        groupLength,
                                        actor,
                                        device,
                                        proofBytes,
                                        proofLength,
                                        package,
                                        packageLength,
                                        &verdict
                                    )
                                )
                            }
                        }
                    }
                }
            }
            // A code this build does not know seats nobody.
            return JoinRequestVerdict(rawValue: verdict) ?? .malformed
        }
    }

    /// Whether this is the first time this device has taken in this signed
    /// seat ask for `groupID`: true once, then false for the same proof while
    /// it could still verify. Asked when a seat ask ARRIVES, before it is
    /// queued, never on a retry of one already taken in, so a delivery service
    /// handing the same ask over again seats nobody twice.
    public func firstSightOfJoinRequest(groupID: Data, proof: Data) throws -> Bool {
        try locked { handle in
            var first = false
            try withBytes(groupID) { group, groupLength in
                try withBytes(proof) { proofBytes, proofLength in
                    try check(
                        peachy_mls_first_sight_of_join_request(
                            handle, group, groupLength, proofBytes, proofLength, &first
                        )
                    )
                }
            }
            return first
        }
    }

    /// Whether this device has already taken in this signed seat ask
    /// (``firstSightOfJoinRequest(groupID:proof:)``), keeping no record: for
    /// an ask that waits in a join inbox and is read again on every pass
    /// until somebody acts on it.
    public func joinRequestSeen(groupID: Data, proof: Data) throws -> Bool {
        try locked { handle in
            var seen = false
            try withBytes(groupID) { group, groupLength in
                try withBytes(proof) { proofBytes, proofLength in
                    try check(
                        peachy_mls_join_request_seen(
                            handle, group, groupLength, proofBytes, proofLength, &seen
                        )
                    )
                }
            }
            return seen
        }
    }

    /// The group's current epoch.
    public func epoch(groupID: Data) throws -> UInt64 {
        try locked { handle in try epochUnlocked(handle, groupID) }
    }

    /// Whether this group's local state is older than what the delivery
    /// service still holds.
    ///
    /// `serverOldestEpoch` is the oldest epoch the delivery service can still serve
    /// (docs/delivery.md §Retention). Equality is NOT behind: a
    /// device at exactly the oldest retained epoch holds the one commit it
    /// needs.
    ///
    /// THE LOCAL SECOND OPINION on `FetchMailboxResponse.lost`, and the reason that flag
    /// is never acted on alone: a client that threw a group away on the
    /// server's word would be a client any delivery service could make forget
    /// every group it holds. A group this device holds no state for answers
    /// false — there is nothing here to be behind with, and nothing to forget.
    public func isBehind(groupID: Data, serverOldestEpoch: UInt64) throws -> Bool {
        do {
            return try locked { handle in
                var behind = false
                try withBytes(groupID) { bytes, length in
                    try check(
                        peachy_mls_group_is_behind(handle, bytes, length, serverOldestEpoch, &behind)
                    )
                }
                return behind
            }
        } catch let error as MLSError where error.code == .noSuchGroup {
            return false
        }
    }

    /// Whether failing to apply `message` strands this device in the group —
    /// off the ratchet for good, exactly as if it had slept past the retention
    /// window (docs/delivery.md §A commit this device cannot
    /// apply).
    ///
    /// Asked after `processCommit` threw on a stream entry. True exactly when
    /// it is the COMMIT at this device's epoch that `processCommit` refused
    /// last AFTER it opened and verified (a member built it, and this
    /// device's policy refused what the rest of the group merged). A commit
    /// that did not open is false at any epoch, because its framing is
    /// anyone's to write: ask the group's head instead
    /// (docs/delivery.md §A commit this device cannot apply). False
    /// too for a replay from an epoch already left, anything that is not a
    /// commit, bytes that do not parse and a group held nowhere here. A
    /// `.storage` failure is transient and the caller's to hold back on first.
    public func commitStrands(groupID: Data, message: Data) throws -> Bool {
        try locked { handle in
            var strands = false
            try withBytes(groupID) { group, groupLength in
                try withBytes(message) { bytes, length in
                    try check(
                        peachy_mls_group_commit_strands(
                            handle, group, groupLength, bytes, length, &strands
                        )
                    )
                }
            }
            return strands
        }
    }

    // MARK: The steward: stamps, the hold, vetoes, repair notices
    //
    // The steward key, not part of this specification. Bindings only: this build
    // READS all of it and writes none of it. The stamp check only alerts, and
    // the hold engages only in a group whose meta names a steward key, which
    // no build writes.

    /// Hand in the SEALED STAMP the delivery service attached to the commit
    /// about to go through ``processCommit(groupID:message:)``
    /// (`MailboxEnvelope.commit_stamp`; docs/delivery.md §The sealed
    /// stamp). Kept in memory for that one commit; empty hands in nothing.
    public func noteCommitStamp(groupID: Data, stamp: Data) throws {
        try locked { handle in
            try withBytes(groupID) { group, groupLength in
                try withBytes(stamp) { bytes, length in
                    try check(
                        peachy_mls_group_note_commit_stamp(handle, group, groupLength, bytes, length)
                    )
                }
            }
        }
    }

    /// What the commit door found checking the last commit it merged against
    /// its sealed stamp, TAKEN, as the core's JSON
    /// (`{"epoch","stamp","mac","steward"}`, plus `"blame"` when the committer
    /// is blamed); nil when no commit merged since the last take. A caller
    /// only alerts on it in this build.
    public func takeCommitCheck(groupID: Data) throws -> String? {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_take_commit_check(handle, bytes, length, &buffer))
            }
            let raw = takeData(&buffer)
            return raw.isEmpty ? nil : String(decoding: raw, as: UTF8.self)
        }
    }

    /// The GROUP HOLD of the group when it holds now, as the core's JSON
    /// (`{"epoch","since","until","reason"}`); nil for none.
    public func groupHold(groupID: Data) throws -> String? {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_hold(handle, bytes, length, &buffer))
            }
            let raw = takeData(&buffer)
            return raw.isEmpty ? nil : String(decoding: raw, as: UTF8.self)
        }
    }

    /// Hold the group for its steward's repair or veto, for `reason` (1 a
    /// refused commit, 2 an unopenable or lost one, 3 a false repair notice).
    /// False, and nothing changes, for a group this device does not count as
    /// enrolled, and for one whose hold already lapsed or was released at its
    /// current epoch (at most one hold an epoch: the caller rejoins).
    public func enterHold(groupID: Data, reason: UInt32) throws -> Bool {
        try locked { handle in
            var held = false
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_enter_hold(handle, bytes, length, reason, &held))
            }
            return held
        }
    }

    /// Release the group's hold, if any: it lapses now and stays on record,
    /// so the group is not held again at this epoch.
    public func releaseHold(groupID: Data) throws {
        try locked { handle in
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_release_hold(handle, bytes, length))
            }
        }
    }

    /// What a commit entry's VETO FRAME means to this device: 0 nothing, 1 a
    /// valid veto of the commit at this device's epoch (skip it and take this
    /// one), 2 a valid veto of a commit this device already merged (rejoin),
    /// 3 a valid veto too far back for this copy to tell (read the group's
    /// head now, through the fork check).
    public func judgeVeto(groupID: Data, entry: Data) throws -> UInt32 {
        try locked { handle in
            var verdict: UInt32 = 0
            try withBytes(groupID) { group, groupLength in
                try withBytes(entry) { bytes, length in
                    try check(
                        peachy_mls_group_judge_veto(handle, group, groupLength, bytes, length, &verdict)
                    )
                }
            }
            return verdict
        }
    }

    /// Judge a REPAIR NOTICE lane frame from `sender` (the MLS sender's
    /// actor id, as the message door reported it) against the verifier this
    /// device's copy had at its epoch: 0 consistent, 1 inconsistent (an admin
    /// repointing the head; holds an enrolled group at most once an epoch), 2
    /// nothing to judge (including a sender the group does not name as an
    /// admin).
    public func checkRepairNotice(groupID: Data, sender: String, wire: Data) throws -> UInt32 {
        try locked { handle in
            var verdict: UInt32 = 0
            try withBytes(groupID) { group, groupLength in
                try withBytes(Data(sender.utf8)) { from, fromLength in
                    try withBytes(wire) { bytes, length in
                        try check(
                            peachy_mls_group_check_repair_notice(
                                handle, group, groupLength, from, fromLength, bytes, length, &verdict
                            )
                        )
                    }
                }
            }
            return verdict
        }
    }

    /// Open FetchCommitAt's `sealed_commit` with this epoch's send key: the
    /// commit envelope as it was placed (FetchCommitAt, not part of this specification).
    public func openFetchedCommit(groupID: Data, sealed: Data) throws -> Data {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try withBytes(sealed) { bytes, length in
                    try check(
                        peachy_mls_group_open_fetched_commit(
                            handle, group, groupLength, bytes, length, &buffer
                        )
                    )
                }
            }
            return takeData(&buffer)
        }
    }

    /// Drop every trace of a group from this device.
    ///
    /// The other half of the rejoin, and everything it does is LOCAL — which is
    /// the point: a device off the ratchet cannot sign a Remove of its own leaf
    /// that anybody would accept. The state goes from storage and not merely
    /// from the open map, so the Welcome a live member's
    /// ``replaceMember(groupID:leafIndex:keyPackage:)`` mints creates the group
    /// fresh rather than colliding with the stale copy.
    ///
    /// Throws ``MLSError``'s no-such-group case for a group this device does
    /// not hold: the caller asking is a caller who believed it held one.
    ///
    /// It KEEPS the people this device last saw in the group, when they name
    /// anybody but this device's own person, until a copy in the id is
    /// confirmed; each person it sees leave in the meantime is dropped from
    /// them, and nobody is added. A later Welcome into the id is drawn
    /// against them: who was added, who is gone, whether the admins changed
    /// (``takeRejoinReport(groupID:)``). They refuse nobody
    /// (docs/delivery.md §A Welcome into a group this device knew).
    /// Reports not taken yet are kept too. A person leaving on purpose calls
    /// ``forgetRememberedRoster(groupID:)`` after it.
    public func forgetGroup(groupID: Data) throws {
        try locked { handle in
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_forget(handle, bytes, length))
            }
        }
    }

    /// Drop the roster ``forgetGroup(groupID:)`` kept for `groupID`: for a
    /// person who LEFT on purpose, so a later Welcome into the id is a new
    /// invitation from whoever sends it. The record of who left and any
    /// report not taken yet go with it. A no-op when nothing is kept.
    public func forgetRememberedRoster(groupID: Data) throws {
        try locked { handle in
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_forget_remembered_roster(handle, bytes, length))
            }
        }
    }

    /// The OLDEST report a Welcome that restored or replaced `groupID` on
    /// this device left, or a head contradicting its copy did, TAKEN (`nil`
    /// when there is nothing left to tell): who re-seated this device (and
    /// from which of its devices, when known, and whether that was a device
    /// of this person's own it does not trust), who came in and who left
    /// while it was away, whether the admins changed, and whether a head
    /// contradicted the copy. Each Welcome leaves its own report, in order:
    /// call until `nil` and draw each as its own lines in the conversation.
    /// Past 32 waiting, a new one is folded into the newest, which then names
    /// only the later re-adder.
    public func takeRejoinReport(groupID: Data) throws -> RejoinReport? {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_take_rejoin_report(handle, bytes, length, &buffer))
            }
            return try Self.decodeRejoinReport(takeData(&buffer))
        }
    }

    /// The OLDEST report waiting for `groupID`, LEFT IN PLACE (`nil` when
    /// there is nothing left to tell): the door the app draws through
    /// (docs/delivery.md §A Welcome into a group this device knew).
    /// Its ``RejoinReport/drawnAtMs`` is `nowMs` the first time a report is
    /// peeked and the same on every later peek: draw its lines at that time,
    /// keyed so a second draw rewrites them, then
    /// ``dropRejoinReport(groupID:id:)`` it and peek again. A report not
    /// dropped is answered again after a restart, so one whose drawing was
    /// cut short by the process dying is drawn after all.
    public func peekRejoinReport(groupID: Data, nowMs: UInt64) throws -> RejoinReport? {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupID) { bytes, length in
                try check(
                    peachy_mls_group_peek_rejoin_report(handle, bytes, length, nowMs, &buffer))
            }
            return try Self.decodeRejoinReport(takeData(&buffer))
        }
    }

    /// Drop the report ``peekRejoinReport(groupID:nowMs:)`` answered with
    /// `id`, once its lines are drawn. Whether one was dropped: false when
    /// none waiting has that id (another process drew and dropped it first).
    @discardableResult
    public func dropRejoinReport(groupID: Data, id: UInt64) throws -> Bool {
        try locked { handle in
            var dropped = false
            try withBytes(groupID) { bytes, length in
                try check(peachy_mls_group_drop_rejoin_report(handle, bytes, length, id, &dropped))
            }
            return dropped
        }
    }

    /// A rejoin report as the core lays it out. An EMPTY buffer is "nothing
    /// to tell"; anything else is a string list `[by, byDevice, untrusted,
    /// flags, item...]`: `untrusted` "1" or "", `flags` letters `a` (admins
    /// changed), `c` (contested); each item `+actor` (added), `-actor`
    /// (departed), `~actor device` (a device left out), `#id`, `@drawnAtMs`.
    static func decodeRejoinReport(_ raw: Data) throws -> RejoinReport? {
        if raw.isEmpty { return nil }
        let items = try decodeStringList(raw)
        guard items.count >= 4 else {
            throw MLSError(code: .codec, message: "a rejoin report cut short")
        }
        let flags = items[3]
        guard !items[0].isEmpty || flags.contains("c") else {
            throw MLSError(code: .codec, message: "a rejoin report without its re-adder")
        }
        var added: [String] = []
        var departed: [String] = []
        var dropped: [RejoinReport.DroppedDevice] = []
        var id: UInt64 = 0
        var drawnAtMs: UInt64 = 0
        for item in items.dropFirst(4) {
            let rest = String(item.dropFirst())
            switch item.first {
            case "+": added.append(rest)
            case "-": departed.append(rest)
            case "~":
                let parts = rest.split(separator: " ", maxSplits: 1).map(String.init)
                guard parts.count == 2 else {
                    throw MLSError(code: .codec, message: "a rejoin report device without its actor")
                }
                dropped.append(RejoinReport.DroppedDevice(actorId: parts[0], deviceId: parts[1]))
            case "#":
                guard let value = UInt64(rest) else {
                    throw MLSError(code: .codec, message: "a rejoin report id that does not read")
                }
                id = value
            case "@":
                guard let value = UInt64(rest) else {
                    throw MLSError(code: .codec, message: "a rejoin report time that does not read")
                }
                drawnAtMs = value
            default:
                throw MLSError(code: .codec, message: "a rejoin report actor without its sign")
            }
        }
        return RejoinReport(
            readdedBy: items[0], readdedByDevice: items[1], added: added,
            readdedByUntrusted: items[2] == "1", departed: departed,
            adminsChanged: flags.contains("a"), contested: flags.contains("c"),
            droppedDevices: dropped, id: id, drawnAtMs: drawnAtMs)
    }

    /// Encrypt an application message carrying a content hint
    /// (docs/sealed-messages.md §Content hints): ``ContentHint``.
    public func encrypt(groupID: Data, plaintext: Data, hint: ContentHint) throws -> Data {
        try locked { handle in
            var message = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try withBytes(plaintext) { bytes, length in
                    try check(
                        peachy_mls_group_encrypt_with_hint(
                            handle, group, groupLength, bytes, length, hint.rawValue, &message
                        )
                    )
                }
            }
            return takeData(&message)
        }
    }

    /// Encrypt an application message for the group under the default
    /// content hint (``ContentHint/default``): no message leaves without one.
    public func encrypt(groupID: Data, plaintext: Data) throws -> Data {
        try locked { handle in
            var message = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try withBytes(plaintext) { bytes, length in
                    try check(
                        peachy_mls_group_encrypt(handle, group, groupLength, bytes, length, &message)
                    )
                }
            }
            return takeData(&message)
        }
    }

    /// Process one incoming message through the MESSAGE door: an application
    /// message only. A commit or a proposal throws ``MLSError/Code/wrongDoor``
    /// before the engine reads it, and nothing moves. Every path that reads a
    /// MESSAGE envelope calls this: a commit merged there would skip the
    /// commit path's roster rows and key checks (`Client::process_message`).
    /// There is no doorless form.
    ///
    /// `receivedAt` is the second the delivery service received the message
    /// (the mailbox envelope's `received_at`, Unix seconds), `0` when the
    /// caller does not know it. A message from a device whose account signed
    /// it out, which this device holds
    /// (``staleLeafRemovable(groupID:leafIndex:revocation:revokedAt:)``), is
    /// read only when it was received before the revocation took effect; an
    /// unknown time counts as after, and it throws
    /// ``MLSError/Code/notFromAMember``. A lapsed sender's NEW message
    /// (docs/identity.md §A lapsed leaf's new messages) throws as
    /// an expired credential.
    public func processMessage(
        groupID: Data, message: Data, receivedAt: Int64 = 0
    ) throws -> Incoming {
        try process(
            groupID: groupID, message: message, door: UInt32(PEACHY_MLS_DOOR_MESSAGE),
            receivedAt: receivedAt)
    }

    /// ``processMessage(groupID:message:receivedAt:)`` for the message inside mailbox
    /// envelope `envelopeID`, with what an application message opens to kept
    /// IN THE SAME WRITE THAT SPENDS ITS KEY until ``releaseOpened(id:)``.
    /// The same envelope handed over again (the app died, or its archive
    /// refused the write, before it stored the words) answers the same
    /// words, not a duplicate (`Client::process_message_as`). An empty id
    /// keeps nothing. `receivedAt` is as
    /// ``processMessage(groupID:message:receivedAt:)``'s.
    public func processMessage(
        groupID: Data, message: Data, keptAs envelopeID: String, receivedAt: Int64 = 0
    ) throws -> Incoming {
        try process(
            groupID: groupID, message: message, door: UInt32(PEACHY_MLS_DOOR_MESSAGE), keptAs: envelopeID,
            receivedAt: receivedAt)
    }

    /// The app's own copy of what envelope `id` opened to is stored: what
    /// ``processMessage(groupID:message:keptAs:)`` kept of it goes. Called
    /// for every envelope acknowledged. True when anything was kept.
    @discardableResult
    public func releaseOpened(id: String) throws -> Bool {
        try locked { handle in
            var released = false
            try id.withCString { idPointer in
                try check(peachy_mls_release_opened(handle, idPointer, &released))
            }
            return released
        }
    }

    /// ``releaseOpened(id:)`` for every envelope in `ids` IN ONE WRITE
    /// (`Client::release_opened_all`): a page's acknowledged envelopes go
    /// together, so the page ends one write rather than one per envelope.
    /// Answers how many held a record.
    @discardableResult
    public func releaseOpened(ids: [String]) throws -> Int {
        guard !ids.isEmpty else { return 0 }
        var joined = Data()
        for id in ids {
            joined.append(contentsOf: Array(id.utf8))
            joined.append(0)
        }
        return try locked { handle in
            var released: UInt32 = 0
            try withBytes(joined) { bytes, length in
                try check(peachy_mls_release_opened_all(handle, bytes, length, &released))
            }
            return Int(released)
        }
    }

    /// THE MAILBOX DOOR (`peachy_mls_group_process_mailbox_entry`): one
    /// opened mailbox entry, routed by BOTH the kind the delivery service put
    /// on the entry (`mailboxKind`: ``MailboxKind/mls`` or
    /// ``MailboxKind/commit``) and the kind sealed inside it
    /// (`envelopeKind`, the ``OpenedEnvelope/kind`` ``openEnvelope(_:)``
    /// answered), never one of them alone. A commit is taken only from a
    /// COMMIT entry, one the arbiter ordered, and a message only from an MLS
    /// entry; anything else, a commit sealed into an MLS entry included,
    /// throws ``MLSError/Code/wrongDoor`` before the engine reads it, so
    /// nothing moves. A seat ask and a call signal throw it too: they are not
    /// group messages (``envelopeDoor(mailboxKind:envelopeKind:)`` says which
    /// reader takes them). Every commit read from a mailbox comes through
    /// here, never through ``processCommit(groupID:message:)``, whose door
    /// the caller picks.
    ///
    /// `receivedAt` is as ``processMessage(groupID:message:receivedAt:)``'s;
    /// the commit path does not read it.
    public func processMailboxEntry(
        groupID: Data, mailboxKind: UInt32, envelopeKind: UInt8, inner: Data, receivedAt: Int64 = 0
    ) throws -> Incoming {
        try process(
            groupID: groupID, message: inner, door: 0, mailbox: (mailboxKind, envelopeKind),
            receivedAt: receivedAt)
    }

    /// Which path an opened mailbox entry takes
    /// (`peachy_mls_envelope_door`), from the kind the delivery service put
    /// on the entry and the kind sealed inside it. A commit only from a
    /// COMMIT entry; a message, a seat ask or a call signal only from an MLS
    /// entry; anything else ``EnvelopeDoor/drop`` (acknowledged unread), as
    /// is a code this build does not know.
    public static func envelopeDoor(mailboxKind: UInt32, envelopeKind: UInt8) -> EnvelopeDoor {
        EnvelopeDoor(rawValue: peachy_mls_envelope_door(mailboxKind, envelopeKind)) ?? .drop
    }

    /// Process one incoming message through the COMMIT door: a commit only.
    /// Anything else throws ``MLSError/Code/wrongDoor`` before the engine
    /// reads it. For a commit that did not come out of a mailbox entry (a
    /// call link's log); a mailbox entry goes through
    /// ``processMailboxEntry(groupID:mailboxKind:envelopeKind:inner:receivedAt:)``,
    /// which also checks the entry's kind.
    ///
    /// A commit is merged before this returns, so `roster(groupID:)` and
    /// `epoch(groupID:)` already describe the new epoch. A commit group policy
    /// refuses throws `.policyRefused` and changes nothing.
    public func processCommit(groupID: Data, message: Data) throws -> Incoming {
        try process(
            groupID: groupID, message: message, door: UInt32(PEACHY_MLS_DOOR_COMMIT), receivedAt: 0)
    }

    private func process(
        groupID: Data, message: Data, door: UInt32, keptAs envelopeID: String? = nil,
        mailbox: (kind: UInt32, envelopeKind: UInt8)? = nil, receivedAt: Int64
    ) throws -> Incoming {
        try locked { handle in
            var incoming = PeachyMlsIncoming()
            try withBytes(groupID) { group, groupLength in
                try withBytes(message) { bytes, length in
                    if let mailbox {
                        try check(
                            peachy_mls_group_process_mailbox_entry(
                                handle,
                                group,
                                groupLength,
                                mailbox.kind,
                                mailbox.envelopeKind,
                                bytes,
                                length,
                                receivedAt,
                                &incoming
                            )
                        )
                    } else if let envelopeID {
                        try envelopeID.withCString { idPointer in
                            try check(
                                peachy_mls_group_process_message_as(
                                    handle,
                                    group,
                                    groupLength,
                                    bytes,
                                    length,
                                    idPointer,
                                    receivedAt,
                                    &incoming
                                )
                            )
                        }
                    } else {
                        try check(
                            peachy_mls_group_process_door(
                                handle,
                                group,
                                groupLength,
                                bytes,
                                length,
                                door,
                                receivedAt,
                                &incoming
                            )
                        )
                    }
                }
            }
            // One free for every buffer inside, whatever shape it turned out
            // to be — including the early return paths below.
            defer { peachy_mls_incoming_free(&incoming) }

            let sender = Identity(
                actorId: string(of: incoming.sender_actor_id),
                deviceId: string(of: incoming.sender_device_id)
            )
            switch incoming.kind {
            case PEACHY_MLS_INCOMING_APPLICATION:
                return .application(
                    data(of: incoming.plaintext),
                    sender: sender,
                    epoch: incoming.epoch
                )
            case PEACHY_MLS_INCOMING_PROPOSAL:
                return .proposalQueued(
                    sender: sender,
                    kind: incoming.proposal_kind,
                    epoch: incoming.epoch
                )
            case PEACHY_MLS_INCOMING_COMMIT:
                return .commit(
                    epoch: incoming.epoch,
                    sender: sender,
                    removedSelf: incoming.removed_self,
                    left: try decodeStringList(data(of: incoming.left_actor_ids))
                )
            case PEACHY_MLS_INCOMING_ECHO:
                return .echo(epoch: incoming.epoch)
            default:
                // A kind this build does not know. Not a crash and not a
                // silent `.echo`: a caller told "nothing happened" would act
                // on it, and an unknown kind is the one case where the wrapper
                // genuinely does not know what happened.
                throw MLSError(
                    code: .other(incoming.kind),
                    message: "unknown incoming kind \(incoming.kind); "
                        + "this binding is older than the library it linked"
                )
            }
        }
    }

    /// Derive a secret from the current epoch (RFC 9420 §8.5).
    ///
    /// `label` namespaces it: two features exporting under different labels
    /// cannot derive each other's. A feature that needs a key bound to the
    /// group gets a derived secret through this door, never the group's own
    /// key material.
    public func exportSecret(
        groupID: Data,
        label: String,
        context: Data = Data(),
        length: Int
    ) throws -> Data {
        try locked { handle in
            var secret = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try label.withCString { labelBytes in
                    try withBytes(context) { contextBytes, contextLength in
                        try check(
                            peachy_mls_group_export_secret(
                                handle,
                                group,
                                groupLength,
                                labelBytes,
                                contextBytes,
                                contextLength,
                                UInt(length),
                                &secret
                            )
                        )
                    }
                }
            }
            return takeData(&secret)
        }
    }

    /// Seal this device's typing frame for a group at its current epoch,
    /// signed by its leaf and stamped (docs/sealed-messages.md
    /// §Typing inside the group): the inner bytes of a kind-4 envelope.
    public func sealTyping(groupID: Data, typing: Bool) throws -> Data {
        try locked { handle in
            var frame = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try check(peachy_mls_group_typing_seal(handle, group, groupLength, typing, &frame))
            }
            return takeData(&frame)
        }
    }

    /// What ``openTyping(groupID:frame:)`` read: the person whose leaf signed
    /// the frame.
    public struct OpenedTyping: Equatable, Sendable {
        public let actorId: String
        public let typing: Bool
    }

    /// Open a typing frame for a group, or nil for one to drop: another epoch,
    /// an author whose leaf did not sign it, a replay, or a stamp more than two
    /// minutes from this device's clock. A device's own person comes back too;
    /// the caller drops it by name.
    public func openTyping(groupID: Data, frame: Data) throws -> OpenedTyping? {
        let json: Data = try locked { handle in
            var out = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try withBytes(frame) { bytes, length in
                    try check(
                        peachy_mls_group_typing_open(handle, group, groupLength, bytes, length, &out))
                }
            }
            return takeData(&out)
        }
        guard
            let object = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
            let actorId = object["actorId"] as? String, !actorId.isEmpty,
            let typing = object["typing"] as? Bool
        else { return nil }
        return OpenedTyping(actorId: actorId, typing: typing)
    }

    /// Derive a secret from the epoch this client's STAGED commit would move
    /// the group to, before it is merged: the next epoch's send key, whose
    /// verifier rides the same `SubmitCommit` as the commit
    /// (`docs/delivery.md` §SubmitCommit). Throws when nothing is staged.
    public func exportPendingSecret(
        groupID: Data,
        label: String,
        context: Data = Data(),
        length: Int
    ) throws -> Data {
        try locked { handle in
            var secret = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try label.withCString { labelBytes in
                    try withBytes(context) { contextBytes, contextLength in
                        try check(
                            peachy_mls_group_export_pending_secret(
                                handle,
                                group,
                                groupLength,
                                labelBytes,
                                contextBytes,
                                contextLength,
                                UInt(length),
                                &secret
                            )
                        )
                    }
                }
            }
            return takeData(&secret)
        }
    }

    // MARK: - Inside the lock

    /// Take the lock, check the client is still open, and hand the body the
    /// handle.
    ///
    /// The handle is passed rather than read from a property so that "is this
    /// client still open?" is answered in exactly one place and cannot be
    /// skipped by a method written later. Kotlin's `MlsClient.locked` has the
    /// same shape for the same reason.
    ///
    /// And under the suspension hold (§Suspension), taken BEFORE the lock: this
    /// is the one door every instance call reaches the store through, so it is
    /// the one place the hold has to be.
    ///
    /// And where a panic closes the client: the library rolled back what the
    /// panicking call wrote and refuses every later call on that handle, so
    /// it is freed here and every call after throws ``MLSError/closed``. The
    /// owner sees ``isOpen`` turn false and opens a new client over the same
    /// store, which reads the last whole operation back.
    func locked<R>(_ body: (OpaquePointer) throws -> R) throws -> R {
        try MLSClient.held {
            lock.lock()
            defer { lock.unlock() }
            guard let handle = openHandle else { throw MLSError.closed }
            do {
                return try body(handle)
            } catch let error as MLSError where error.code == .panic {
                openHandle = nil
                peachy_mls_client_free(handle)
                throw error
            }
        }
    }

    /// `epoch`, for callers that already hold the lock. `NSLock` is not
    /// recursive, so a public method calling another public method here would
    /// deadlock rather than misbehave.
    private func epochUnlocked(_ handle: OpaquePointer, _ groupID: Data) throws -> UInt64 {
        var epoch: UInt64 = 0
        try withBytes(groupID) { group, groupLength in
            try check(peachy_mls_group_epoch(handle, group, groupLength, &epoch))
        }
        return epoch
    }

    /// The epoch a commit just staged over this group WOULD produce.
    ///
    /// One past where the group is, because a staged commit has not moved it —
    /// and this is the number the delivery service wants, since a commit is
    /// submitted under the epoch it produces. It stops being a guess the moment
    /// ``mergePendingCommit(groupID:)`` returns the same value.
    private func stagedEpoch(_ handle: OpaquePointer, _ groupID: Data) throws -> UInt64 {
        try epochUnlocked(handle, groupID) + 1
    }

    func check(_ status: Int32) throws {
        try MLSClient.checkStatus(status)
    }

    /// The same check, reachable from the enrollment statics, which have no
    /// instance and no lock to take. Those calls touch no client state — the
    /// last-error slot is thread-local either way.
    static func checkStatus(_ status: Int32) throws {
        guard status != PEACHY_MLS_OK else { return }
        // Read the message here, on the thread that made the call and before
        // any other call can land: the slot is thread-local and lives only
        // until this thread's next `peachy_mls_*` call.
        throw MLSError(code: MLSError.Code(status), message: lastErrorMessage())
    }
}

// MARK: - Suspension

/// KEEPING THE PROCESS AWAKE WHILE THE STORE IS IN USE.
///
/// iOS kills a process it suspends while that process holds a lock on a file
/// in a shared container (`0xdead10cc`). The Apple apps keep this client's
/// SQLite store in the app group, so the notification service extension can
/// open it. The store is WAL with a plaintext header, and iOS lets a WAL
/// reader on a file it recognizes by that header be suspended (GRDB's
/// suspension leaves WAL reads alone for this reason); a call that writes holds the WAL write lock from its first write to
/// its commit, every read in between included, and that is the kill.
/// A shipped iOS build was killed twelve
/// seconds after launch with one thread inside `init` here,
/// `peachy_mls_client_open` loading a group, `sqlite3_step` in `pread` — a
/// read, but inside the write transaction the open's rewrite of the signature
/// key had begun. The core no longer writes on an open of an existing store
/// (`Client::new`, `mls/core/src/group.rs`), and the hold below covers the
/// calls that do write. No call returns with the transaction open, a staged
/// commit's included, so the hold ending with the call is the lock ending
/// with it: nothing is held while the app awaits the delivery service.
///
/// The cure is the app's (the Apple apps' suspension hold,
/// a background assertion held exactly as long as the lock), and this package
/// cannot see the app, so the app installs it here once per process with
/// ``holdSuspension(with:)``. Every store-touching entry point — `init`,
/// ``close()``, `deinit` and everything through `locked` — then runs inside
/// it. The statics touch no store and are not held. With nothing installed (a
/// test, a Mac without suspension) a call runs bare.
extension MLSClient {
    /// Run every later store-touching call inside `hold`, which must call the
    /// body it is given exactly once, synchronously, on the calling thread.
    /// Replaces any hold installed before.
    public static func holdSuspension(with hold: @escaping @Sendable (_ body: () -> Void) -> Void) {
        suspension.set(hold)
    }

    /// Whether a hold is installed.
    public static var holdsSuspension: Bool { suspension.get() != nil }

    static func held<R>(_ body: () throws -> R) throws -> R {
        guard let hold = suspension.get() else { return try body() }
        var outcome: Result<R, Error>?
        hold { outcome = Result { try body() } }
        guard let outcome else {
            preconditionFailure("an MLSClient suspension hold did not run its body")
        }
        return try outcome.get()
    }

    static func heldQuietly(_ body: () -> Void) {
        guard let hold = suspension.get() else { return body() }
        hold(body)
    }

    private static let suspension = SuspensionSlot()
}

private final class SuspensionSlot: @unchecked Sendable {
    private let lock = NSLock()
    private var hold: (@Sendable (_ body: () -> Void) -> Void)?

    func get() -> (@Sendable (_ body: () -> Void) -> Void)? {
        lock.lock()
        defer { lock.unlock() }
        return hold
    }

    func set(_ new: @escaping @Sendable (_ body: () -> Void) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        hold = new
    }
}

// MARK: - Buffers

/// Copy a buffer's bytes out and free it. The `Data` owns its own storage; the
/// C allocation is gone by the time this returns.
func takeData(_ buffer: inout PeachyMlsBuffer) -> Data {
    defer { peachy_mls_buffer_free(&buffer) }
    return data(of: buffer)
}

func takeString(_ buffer: inout PeachyMlsBuffer) -> String {
    defer { peachy_mls_buffer_free(&buffer) }
    return string(of: buffer)
}

// MARK: - String lists

/// A LIST OF IDS ACROSS THE C DOOR (`mls/cabi`): a u32 big-endian item count,
/// then each item as a u32 big-endian byte length and that many UTF-8 bytes.
/// Framed rather than joined by a separator, so no id can split itself into
/// two or hide in its neighbor, whatever it holds.
func encodeStringList(_ items: [String]) -> Data {
    encodeByteList(items.map { Data($0.utf8) })
}

/// The same frame around raw items: the KeyPackages of
/// ``MLSClient/seatFounding(groupID:keyPackages:ownKeyPackage:)``.
func encodeByteList(_ items: [Data]) -> Data {
    var out = Data()
    appendBigEndianUInt32(&out, UInt32(items.count))
    for bytes in items {
        appendBigEndianUInt32(&out, UInt32(bytes.count))
        out.append(bytes)
    }
    return out
}

/// Read what ``encodeStringList(_:)`` writes, STRICTLY: a buffer that is
/// truncated, has bytes left over, or holds an item that is not UTF-8 throws
/// (``MLSError/Code/codec``) rather than answering part of the list. An empty
/// buffer is the empty list.
func decodeStringList(_ data: Data) throws -> [String] {
    try decodeFramedList(data, what: "string list").map { (item: Data) throws -> String in
        guard let text = String(data: item, encoding: .utf8) else {
            throw MLSError(code: .codec, message: "malformed string list: an item that is not UTF-8")
        }
        return text
    }
}

/// Read what ``encodeByteList(_:)`` writes, as strictly as
/// ``decodeStringList(_:)`` reads strings: the proposals of
/// ``MLSClient/beginLeave(groupId:)`` and ``MLSClient/followLeave(groupId:message:)``.
/// A partial list is never answered, because a leave that sent only some of
/// its proposals would keep a device of this person in the group.
func decodeByteList(_ data: Data) throws -> [Data] {
    try decodeFramedList(data, what: "byte list")
}

/// The frame both decoders share: a u32 big-endian count, then each item as a
/// u32 big-endian length and its bytes, with nothing left over.
private func decodeFramedList(_ data: Data, what: String) throws -> [Data] {
    if data.isEmpty { return [] }
    let bytes = [UInt8](data)
    var at = 0
    func malformed(_ why: String) -> MLSError {
        MLSError(code: .codec, message: "malformed \(what): \(why)")
    }
    func readLength() throws -> Int {
        guard bytes.count - at >= 4 else { throw malformed("truncated length") }
        var value: UInt32 = 0
        for offset in 0..<4 {
            value = (value << 8) | UInt32(bytes[at + offset])
        }
        at += 4
        return Int(value)
    }
    let count = try readLength()
    var items: [Data] = []
    // Every item takes at least its four length bytes: a count the buffer
    // cannot hold reserves nothing it would never fill.
    items.reserveCapacity(min(count, (bytes.count - at) / 4))
    for _ in 0..<count {
        let length = try readLength()
        guard bytes.count - at >= length else { throw malformed("truncated item") }
        items.append(Data(bytes[at..<(at + length)]))
        at += length
    }
    guard at == bytes.count else { throw malformed("trailing bytes") }
    return items
}

private func appendBigEndianUInt32(_ out: inout Data, _ value: UInt32) {
    out.append(UInt8(truncatingIfNeeded: value >> 24))
    out.append(UInt8(truncatingIfNeeded: value >> 16))
    out.append(UInt8(truncatingIfNeeded: value >> 8))
    out.append(UInt8(truncatingIfNeeded: value))
}

/// Copy without freeing — for the buffers inside a `PeachyMlsIncoming`, which
/// `peachy_mls_incoming_free` releases in one call.
private func data(of buffer: PeachyMlsBuffer) -> Data {
    guard let bytes = buffer.data, buffer.len > 0 else { return Data() }
    return Data(bytes: bytes, count: Int(buffer.len))
}

private func string(of buffer: PeachyMlsBuffer) -> String {
    // The ABI's identity buffers are UTF-8 by construction (they come from
    // Rust `String`s), so a replacement character here would mean memory
    // corruption rather than a bad input. Decoding leniently anyway: a
    // diagnostic that renders is worth more than a trap.
    String(decoding: data(of: buffer), as: UTF8.self)
}

/// Hand `data`'s bytes to a C call.
///
/// The ABI reads a null pointer as an error even at length zero, and an empty
/// `Data` has no base address — so an empty message would come back as
/// `invalidArgument` instead of being sent. A pointer to a local stands in;
/// with a length of 0 the callee never reads through it.
func withBytes<R>(
    _ data: Data,
    _ body: (UnsafePointer<UInt8>, UInt) throws -> R
) rethrows -> R {
    if data.isEmpty {
        var sentinel: UInt8 = 0
        return try withUnsafePointer(to: &sentinel) { try body($0, 0) }
    }
    return try data.withUnsafeBytes { raw -> R in
        guard let base = raw.bindMemory(to: UInt8.self).baseAddress else {
            var sentinel: UInt8 = 0
            return try withUnsafePointer(to: &sentinel) { try body($0, 0) }
        }
        return try body(base, UInt(data.count))
    }
}

/// `String.withCString`, but `nil` is a meaning rather than a missing argument.
///
/// The C ABI reads a NULL `store_path` as "no file, keep this device's state in
/// memory" (`mls/cabi/src/lib.rs`), so the absence has to survive the crossing.
/// Writing it as a branch at the call site instead would mean two spellings of
/// the same seven-argument call, which is two places for an argument to end up
/// in the wrong position.
/// [withBytes] for an optional buffer: `nil` is a NULL pointer and a zero
/// length, which the C door reads as "absent" (the store key).
private func withOptionalBytes<R>(
    _ data: Data?,
    _ body: (UnsafePointer<UInt8>?, UInt) throws -> R
) rethrows -> R {
    guard let data else { return try body(nil, 0) }
    return try withBytes(data) { try body($0, $1) }
}

private func withOptionalCString<R>(
    _ string: String?,
    _ body: (UnsafePointer<CChar>?) throws -> R
) rethrows -> R {
    guard let string else { return try body(nil) }
    return try string.withCString { try body($0) }
}
