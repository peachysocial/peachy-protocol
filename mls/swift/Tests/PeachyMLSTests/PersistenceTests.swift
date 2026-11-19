// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// State survives the client that made it.
///
/// `mls/core/tests/persistence.rs` proves the same thing in Rust and
/// `mls/cabi/tests/abi.rs` through the C door. This is the third layer: that
/// the Swift wrapper passes a path down instead of dropping it, that `deinit`
/// leaves a readable database behind rather than a half-written one, and that a
/// second `MLSClient` on the same file finds its groups.
///
/// The fourth layer — that the file lands in the right place on a real device
/// and is kept out of iCloud — is what `testAStoreURLIsExcludedFromBackup`
/// covers. It is a fact about `FileManager` and not about MLS, and it is here
/// because the consequence of getting it wrong is a device's ratchet secrets
/// restored onto a second phone.
final class PersistenceTests: XCTestCase {
    private let group = Data("peachy-swift-persistent".utf8)

    /// A directory that dies with the test, so nothing here depends on what a
    /// previous run left behind.
    private func scratch(_ name: String) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("PeachyMLSTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        return directory.appendingPathComponent(name, isDirectory: false)
    }

    func testAGroupSurvivesTheClientThatCreatedIt() throws {
        let issuer = try TestIssuer()
        let store = try scratch("ada.sqlite")

        // Bo is ephemeral throughout: one durable side is all this is about,
        // and it keeps "where did that come from" unambiguous.
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 2)
        let keyPackage = try bo.generateKeyPackage()

        var addEpoch: UInt64 = 0
        do {
            let ada = try issuer.client(
                actorId: "actor-ada",
                deviceId: "device-ada",
                tag: 1,
                storePath: store.path
            )
            try ada.createGroup(id: group)
            let add = try ada.addMember(groupID: group, keyPackage: keyPackage)
            try ada.mergePendingCommit(groupID: group)
            addEpoch = add.epoch
            let welcome = try XCTUnwrap(add.welcome)
            XCTAssertEqual(try bo.join(welcome: welcome), group)
        }
        // `ada` is gone: its handle freed, its SQLite connection closed.

        XCTAssertTrue(
            FileManager.default.fileExists(atPath: store.path),
            "the store is a real file, not a path that was ignored"
        )

        let reopened = try issuer.client(
            actorId: "actor-ada",
            deviceId: "device-ada",
            tag: 1,
            storePath: store.path
        )
        XCTAssertEqual(try reopened.epoch(groupID: group), addEpoch, "it came back at its epoch")
        XCTAssertEqual(try reopened.roster(groupID: group).count, 2)

        // The proof that it is the ratchet and not just the metadata: Bo speaks
        // at the epoch the first client committed, and the second one reads it.
        let outbound = try bo.encrypt(groupID: group, plaintext: Data("still here?".utf8))
        guard case let .application(heard, sender, _) = try reopened.processMessage(
            groupID: group,
            message: outbound
        ) else {
            return XCTFail("the reopened client should have read an application message")
        }
        XCTAssertEqual(heard, Data("still here?".utf8))
        XCTAssertEqual(sender.deviceId, "device-bo")

        // And it can still speak, which needs its own signature key back.
        let reply = try reopened.encrypt(groupID: group, plaintext: Data("still here.".utf8))
        guard case let .application(back, _, _) = try bo.processMessage(groupID: group, message: reply)
        else {
            return XCTFail("bo should have read the reply")
        }
        XCTAssertEqual(back, Data("still here.".utf8))
    }

    /// A KEY PACKAGE PUBLISHED IN ONE LAUNCH IS JOINED IN THE NEXT, and that
    /// gap is the whole shape of enrollment.
    ///
    /// Everything else in this file reopens a client that was already IN a
    /// group. The enrollment path never is: a device publishes a pool of key
    /// packages the first time it opens, the app is closed, and hours later
    /// somebody adds it to a conversation with one of them. Joining that
    /// Welcome needs the PRIVATE halves — the init key and the encryption key
    /// minted beside the package — read back out of the store the earlier
    /// launch wrote them to.
    ///
    /// Nothing proved that. `testAGroupSurvivesTheClientThatCreatedIt` keeps
    /// its key package and its join inside one client's lifetime, so a store
    /// that persisted groups and lost unconsumed key-package secrets would
    /// pass this whole file — and fail in the only way a product ever meets
    /// it: an empty bubble on the recipient's screen, with the Welcome already
    /// marked consumed on the server and nothing left to retry.
    func testAKeyPackageOutlivesTheLaunchThatPublishedIt() throws {
        let issuer = try TestIssuer()
        let store = try scratch("bo.sqlite")

        // LAUNCH ONE: Bo enrolls and publishes, exactly as a device does when
        // it opens for the first time, and then goes away.
        let published: KeyPackage
        do {
            let bo = try issuer.client(
                actorId: "actor-bo", deviceId: "device-bo", tag: 2, storePath: store.path)
            published = try bo.generateKeyPackageWithRef().keyPackage
        }

        // Somebody adds him with it while he is not running.
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 1)
        try ada.createGroup(id: group)
        let add = try ada.addMember(groupID: group, keyPackage: published)
        try ada.mergePendingCommit(groupID: group)
        let welcome = try XCTUnwrap(add.welcome)

        // LAUNCH TWO: same store, new client, and the Welcome has to open.
        let bo = try issuer.client(
            actorId: "actor-bo", deviceId: "device-bo", tag: 2, storePath: store.path)
        XCTAssertEqual(
            try bo.join(welcome: welcome), group,
            "the private halves of a published key package did not survive the launch "
                + "that published it")

        // And the group is real on the other side of it, not merely accepted.
        let outbound = try ada.encrypt(groupID: group, plaintext: Data("you are in.".utf8))
        guard case let .application(heard, _, _) = try bo.processMessage(
            groupID: group, message: outbound)
        else {
            return XCTFail("the reopened client joined but could not read the group")
        }
        XCTAssertEqual(heard, Data("you are in.".utf8))
    }

    /// Two files are two devices. It would be an easy and invisible mistake for
    /// a path to be ignored and every client to share one process-wide store —
    /// and everything else in this file would still pass.
    func testTwoStoresAreTwoDevices() throws {
        let issuer = try TestIssuer()
        let ada = try issuer.client(
            actorId: "actor-ada",
            deviceId: "device-ada",
            tag: 1,
            storePath: try scratch("ada.sqlite").path
        )
        let bo = try issuer.client(
            actorId: "actor-bo",
            deviceId: "device-bo",
            tag: 2,
            storePath: try scratch("bo.sqlite").path
        )

        try ada.createGroup(id: group)
        XCTAssertThrowsError(try bo.epoch(groupID: group)) { error in
            XCTAssertEqual((error as? MLSError)?.code, .noSuchGroup)
        }
    }

    /// An unopenable path is a thrown `.storage`, never a quiet fall back to
    /// memory. A client that persisted nothing but said nothing about it is the
    /// failure this whole slice exists to rule out.
    func testAnUnopenableStoreThrowsRatherThanForgetting() throws {
        let issuer = try TestIssuer()
        let directory = try scratch("a-directory")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        XCTAssertThrowsError(
            try issuer.client(
                actorId: "actor-ada",
                deviceId: "device-ada",
                tag: 1,
                storePath: directory.path
            )
        ) { error in
            XCTAssertEqual((error as? MLSError)?.code, .storage)
            XCTAssertFalse((error as? MLSError)?.message.isEmpty ?? true)
        }
    }

    /// `storePath: nil` is still a working client. It just forgets.
    func testAnAbsentPathIsAnEphemeralClient() throws {
        let issuer = try TestIssuer()
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 1)
        try ada.createGroup(id: group)
        XCTAssertEqual(try ada.roster(groupID: group).count, 1)
    }

    /// The URL door creates its directory, opens the store there, and marks all
    /// three SQLite files backup-excluded.
    func testAStoreURLIsExcludedFromBackup() throws {
        let issuer = try TestIssuer()
        // Deliberately two levels deep and not created: the convenience
        // initializer owes the caller the directory, because SQLite will not
        // make one and the failure otherwise is an opaque `unable to open
        // database file`.
        let url = try scratch("nested").appendingPathComponent("more/ada.sqlite")

        let seed = TestIssuer.deviceSeed(1)
        let token = try issuer.credential(
            actorId: "actor-ada",
            deviceId: "device-ada",
            deviceSeed: seed
        )
        let ada = try MLSClient(
            credential: token,
            signatureSeed: seed,
            trustedKeysJSON: issuer.trustedKeysJSON,
            storeURL: url,
            ownAccountIdentity: try TestIssuer.heldIdentity(actorId: "actor-ada")
        )
        try ada.createGroup(id: group)

        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))

        let values = try url.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(
            values.isExcludedFromBackup,
            true,
            "a device's ratchet secrets must not be restorable onto a second device"
        )

        // And signing out really removes it, journal files included.
        MLSClient.destroyStore(at: url)
        for suffix in ["", "-wal", "-shm"] {
            XCTAssertFalse(
                FileManager.default.fileExists(atPath: url.path + suffix),
                "\(url.lastPathComponent)\(suffix) should be gone"
            )
        }
    }

    /// The conventional location is under Application Support and per device.
    func testTheConventionalStoreURLIsPerDevice() {
        let container = FileManager.default.temporaryDirectory
        let one = MLSClient.storeURL(forDevice: "device-ada", in: container)
        let two = MLSClient.storeURL(forDevice: "device-bo", in: container)

        XCTAssertNotEqual(one, two)
        XCTAssertEqual(one.deletingLastPathComponent(), two.deletingLastPathComponent())
        XCTAssertEqual(one.lastPathComponent, "device-ada.sqlite")
    }

    /// THE APPLE KEYSPEC: 48 bytes, a key and a salt, with the file's first 32
    /// bytes left as SQLite's own header (`mls/core/src/sqlite.rs` §The
    /// plaintext header) — what the apps pass, because iOS kills a suspended
    /// app holding a lock on an app-group file it cannot recognize as SQLite.
    /// The header is SQLite's, nothing after it is (the table name never
    /// appears), the group comes back under the keyspec, and neither the bare
    /// key nor no key opens it.
    func testAKeyspecStoreKeepsSQLitesHeaderAndHidesEverythingElse() throws {
        let issuer = try TestIssuer()
        let store = try scratch("ada.sqlite")
        var keyspec = Data(repeating: 0x5c, count: 48)
        keyspec.replaceSubrange(32..<48, with: Data(repeating: 0x21, count: 16))

        do {
            let ada = try issuer.client(
                actorId: "actor-ada", deviceId: "device-ada", tag: 1,
                storePath: store.path, storeKey: keyspec)
            try ada.createGroup(id: group)
        }

        let bytes = try Data(contentsOf: store)
        XCTAssertEqual(bytes.prefix(16), Data("SQLite format 3\0".utf8), "the header stays SQLite's")
        XCTAssertNotEqual(bytes[20], 0, "SQLCipher reserves room on every page")
        let wal = (try? Data(contentsOf: URL(fileURLWithPath: store.path + "-wal"))) ?? Data()
        for file in [bytes, wal] {
            XCTAssertNil(file.range(of: Data("mls_kv".utf8)), "nothing after the header is readable")
        }

        XCTAssertThrowsError(
            try issuer.client(
                actorId: "actor-ada", deviceId: "device-ada", tag: 1, storePath: store.path),
            "no key must not open it")
        XCTAssertThrowsError(
            try issuer.client(
                actorId: "actor-ada", deviceId: "device-ada", tag: 1, storePath: store.path,
                storeKey: keyspec.prefix(32)),
            "the key without its salt must not open it")
        let reopened = try issuer.client(
            actorId: "actor-ada", deviceId: "device-ada", tag: 1,
            storePath: store.path, storeKey: keyspec)
        XCTAssertEqual(try reopened.roster(groupID: group).count, 1)
    }

    /// A STORE WRITTEN IN THE CLEAR, opened with a key, throws
    /// `.plaintextStore` and is not touched; `encryptStoreInPlace` turns it
    /// into one under the key with every group kept, and it then opens under
    /// that key and no longer without one.
    func testAPlaintextStoreIsNamedAndEncryptedInPlace() throws {
        let issuer = try TestIssuer()
        let store = try scratch("ada.sqlite")
        let key = Data(repeating: 0x3a, count: 32)
        do {
            let ada = try issuer.client(
                actorId: "actor-ada", deviceId: "device-ada", tag: 1, storePath: store.path)
            try ada.createGroup(id: group)
        }
        XCTAssertThrowsError(
            try issuer.client(
                actorId: "actor-ada", deviceId: "device-ada", tag: 1, storePath: store.path, storeKey: key)
        ) { error in
            XCTAssertEqual((error as? MLSError)?.code, .plaintextStore)
        }
        try MLSClient.encryptStoreInPlace(path: store.path, key: key)
        let reopened = try issuer.client(
            actorId: "actor-ada", deviceId: "device-ada", tag: 1, storePath: store.path, storeKey: key)
        XCTAssertEqual(try reopened.roster(groupID: group).count, 1, "the group survived the migration")
        reopened.close()
        XCTAssertThrowsError(
            try MLSClient.encryptStoreInPlace(path: store.path, key: key), "an encrypted store is refused"
        ) { error in
            XCTAssertEqual((error as? MLSError)?.code, .invalidArgument)
        }
    }

    /// `storeMustExist` opens only a store that is there: a path with no
    /// file throws and creates nothing.
    func testAStoreThatMustExistIsNotCreated() throws {
        let issuer = try TestIssuer()
        let missing = try scratch("gone.sqlite")
        XCTAssertThrowsError(
            try issuer.client(
                actorId: "actor-ada", deviceId: "device-ada", tag: 1, storePath: missing.path,
                storeMustExist: true)
        ) { error in
            XCTAssertEqual((error as? MLSError)?.code, .invalidArgument)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: missing.path), "nothing was created")
    }

    /// The linked library speaks the ABI this package was compiled against.
    func testTheLinkedLibrarysABIMatchesTheHeader() {
        XCTAssertTrue(MLSClient.abiMatches, "library \(MLSClient.abiVersion), header \(MLSClient.headerABIVersion)")
    }

    /// WHAT A MESSAGE OPENED TO OUTLIVES A LAUNCH THAT DIED BEFORE STORING
    /// IT (`Client::process_message_as`). Opening spends the ratchet key; an
    /// app killed between the open and its archive write met the same
    /// envelope again as a duplicate, and the words were gone. Opened under
    /// its envelope id, the next launch is handed the same words until it
    /// releases them.
    func testAnOpenedMessageOutlivesALaunchThatDiedBeforeStoringIt() throws {
        let issuer = try TestIssuer()
        let store = try scratch("bo-kept.sqlite")
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 1)
        let message: Data
        do {
            let bo = try issuer.client(
                actorId: "actor-bo", deviceId: "device-bo", tag: 2, storePath: store.path)
            try ada.createGroup(id: group)
            let add = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
            try ada.mergePendingCommit(groupID: group)
            XCTAssertEqual(try bo.join(welcome: try XCTUnwrap(add.welcome)), group)
            message = try ada.encrypt(groupID: group, plaintext: Data("dinner at eight".utf8))
            guard case let .application(heard, _, _) = try bo.processMessage(
                groupID: group, message: message, keptAs: "env-1")
            else {
                return XCTFail("bo should have read the message")
            }
            XCTAssertEqual(heard, Data("dinner at eight".utf8))
        }
        // The launch died before its archive write.

        let bo = try issuer.client(
            actorId: "actor-bo", deviceId: "device-bo", tag: 2, storePath: store.path)
        XCTAssertThrowsError(try bo.processMessage(groupID: group, message: message)) { error in
            XCTAssertEqual((error as? MLSError)?.code, .duplicate, "the key was spent")
        }
        guard case let .application(again, sender, _) = try bo.processMessage(
            groupID: group, message: message, keptAs: "env-1")
        else {
            return XCTFail("the kept words should have come back")
        }
        XCTAssertEqual(again, Data("dinner at eight".utf8))
        XCTAssertEqual(sender.actorId, "actor-ada")

        // A page's ids go in one write; one that kept nothing is passed over.
        XCTAssertEqual(try bo.releaseOpened(ids: ["env-1", "env-unknown"]), 1)
        XCTAssertFalse(try bo.releaseOpened(id: "env-1"), "released once")
        XCTAssertThrowsError(
            try bo.processMessage(groupID: group, message: message, keptAs: "env-1")
        ) { error in
            XCTAssertEqual((error as? MLSError)?.code, .duplicate)
        }
    }
}
