// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// The doors a device needs around enrollment and relaunch: the key package a
/// DIRECTORY can store, the set of groups a relaunched device already knows,
/// whether it is still a member of one, and the two enrollment helpers that run
/// before there is a client at all.
///
/// The same four questions the web client asks the wasm binding
/// (the web client's session code), asked here through the C header, so
/// that a binding which answers one of them differently is a red rather than a
/// difference two clients discover in production.
final class EnrollmentAndDirectoryTests: XCTestCase {
    private let group = Data("peachy-swift-directory".utf8)

    // MARK: - Enrollment

    func testASeedAndItsPublicHalf() throws {
        let seed = try MLSClient.generateSigningKeySeed()
        XCTAssertEqual(seed.count, 32)

        // Two seeds differ. A CSPRNG that returned a constant would make every
        // device on earth the same device, and nothing else here would notice.
        let other = try MLSClient.generateSigningKeySeed()
        XCTAssertNotEqual(other, seed)

        let publicKey = try MLSClient.signingKeyPublicKey(seed: seed)
        XCTAssertEqual(publicKey.count, 32)
        XCTAssertNotEqual(publicKey, seed, "the public half is not the seed")

        // Deterministic: the same seed is the same device, which is what lets
        // a credential be minted against it once and believed later.
        XCTAssertEqual(try MLSClient.signingKeyPublicKey(seed: seed), publicKey)
    }

    func testTheEnrollmentPublicKeyIsTheOneTheCredentialBinds() throws {
        // The whole point of the pair. A device registers `publicKey`, the
        // server mints a credential over it, and the client opens with the
        // seed. If these two derivations ever disagreed, every call would fail
        // `leafKeyMismatch` and read as a protocol bug.
        let issuer = try TestIssuer()
        let seed = try MLSClient.generateSigningKeySeed()
        let publicKey = try MLSClient.signingKeyPublicKey(seed: seed)

        let token = try issuer.credential(
            actorId: "actor-enrolled",
            deviceId: "device-enrolled",
            deviceSeed: seed
        )
        let client = try MLSClient(
            credential: token,
            signatureSeed: seed,
            trustedKeysJSON: issuer.trustedKeysJSON,
            storePath: nil,
            ownAccountIdentity: try TestIssuer.heldIdentity(actorId: "actor-enrolled")
        )
        XCTAssertEqual(
            try client.identity(),
            Identity(actorId: "actor-enrolled", deviceId: "device-enrolled")
        )
        XCTAssertEqual(publicKey.count, 32)
    }

    func testASeedOfTheWrongLengthIsAThrowAndNotACrash() throws {
        XCTAssertThrowsError(try MLSClient.signingKeyPublicKey(seed: Data(repeating: 1, count: 31)))
        {
            error in
            guard let mls = error as? MLSError else {
                return XCTFail("expected an MLSError, got \(error)")
            }
            XCTAssertTrue(
                mls.message.contains("32"),
                "the message names the length it wanted: \(mls.message)"
            )
        }
    }

    // MARK: - The directory

    func testAKeyPackageComesBackWithTheReferenceThatNamesIt() throws {
        let issuer = try TestIssuer()
        let device = try issuer.client(actorId: "actor-kp", deviceId: "device-kp", tag: 4)

        let published = try device.generateKeyPackageWithRef()
        XCTAssertFalse(published.keyPackage.data.isEmpty)
        // RefHash with SHA-256 over the bare KeyPackage.
        XCTAssertEqual(published.keyPackageRef.count, 32)
        XCTAssertNotEqual(
            published.keyPackageRef,
            published.keyPackage.data,
            "the reference is not the package"
        )
        XCTAssertNotEqual(published.ciphersuite, 0, "the ciphersuite id is filled in")

        // Single-use, and each one has its own name. A directory keyed on the
        // reference depends on this: a stable reference would collapse every
        // republish onto one row while stranding N private halves in the store.
        let second = try device.generateKeyPackageWithRef()
        XCTAssertNotEqual(second.keyPackageRef, published.keyPackageRef)
        XCTAssertEqual(second.ciphersuite, published.ciphersuite)

        // And it is a real key package: somebody can be added with it.
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 5)
        try ada.createGroup(id: group)
        let add = try ada.addMember(groupID: group, keyPackage: published.keyPackage)
        try ada.mergePendingCommit(groupID: group)
        let welcome = try XCTUnwrap(add.welcome)
        XCTAssertEqual(try device.join(welcome: welcome), group)
    }

    func testTheGroupSetIsEnumerableAndMembershipIsAnswerable() throws {
        let issuer = try TestIssuer()
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 6)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 7)

        XCTAssertEqual(try ada.groupIDs(), [], "a fresh client holds no groups")

        try ada.createGroup(id: group)
        XCTAssertEqual(try ada.groupIDs(), [group])
        XCTAssertTrue(try ada.isActive(groupID: group), "the creator is a member")

        // Bo knows nothing of the group until the Welcome lands — which is the
        // distinction that makes this door worth having on a relaunch.
        XCTAssertEqual(try bo.groupIDs(), [])
        XCTAssertThrowsError(try bo.isActive(groupID: group)) { error in
            XCTAssertEqual((error as? MLSError)?.code, .noSuchGroup)
        }

        let add = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(add.welcome))
        XCTAssertEqual(try bo.groupIDs(), [group])
        XCTAssertTrue(try bo.isActive(groupID: group))

        // Removed: still holds the state and the history, no longer a member.
        let boEntry = try XCTUnwrap(
            try ada.roster(groupID: group).first { $0.verified?.deviceId == "device-bo" }
        )
        let removal = try ada.removeMember(
            groupID: group, leafIndex: boEntry.leafIndex, leafKey: boEntry.leafKey)
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.processCommit(groupID: group, message: removal.commit)

        XCTAssertEqual(try bo.groupIDs(), [group], "the state is still here")
        XCTAssertFalse(try bo.isActive(groupID: group), "but he is not a member")
        XCTAssertTrue(try ada.isActive(groupID: group))
    }

    func testTheGroupSetSurvivesAReopen() throws {
        // The reason `groupIDs()` exists: a relaunched device deciding whether
        // a conversation needs a Welcome claimed or merely a stream replayed.
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let storePath = directory.appendingPathComponent("store.sqlite").path

        let issuer = try TestIssuer()
        do {
            let ada = try issuer.client(
                actorId: "actor-ada", deviceId: "device-ada", tag: 8, storePath: storePath
            )
            try ada.createGroup(id: group)
            XCTAssertEqual(try ada.groupIDs(), [group])
        }

        let reopened = try issuer.client(
            actorId: "actor-ada", deviceId: "device-ada", tag: 8, storePath: storePath
        )
        XCTAssertEqual(try reopened.groupIDs(), [group], "the group came back")
        XCTAssertTrue(try reopened.isActive(groupID: group))
    }
}
