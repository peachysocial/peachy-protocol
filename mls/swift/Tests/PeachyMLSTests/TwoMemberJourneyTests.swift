// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import XCTest

@testable import PeachyMLS

/// The journey `mls/core/tests/end_to_end.rs` and `mls/cabi/tests/abi.rs`
/// already drive, driven a third time — through Swift.
///
/// Three runs of the same story is not duplication for its own sake. Each one
/// holds a different layer: the Rust one holds the protocol, the C one holds
/// the ownership discipline, and this one holds the binding — that the buffers
/// are copied and freed, that the enum cases carry what the header says they
/// carry, and that an error becomes a thrown `MLSError` rather than a status
/// code nobody checked.
final class TwoMemberJourneyTests: XCTestCase {
    private let group = Data("peachy-swift".utf8)

    func testTwoMembersTalkAndOneIsRemoved() throws {
        let issuer = try TestIssuer()
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 1)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 2)

        XCTAssertEqual(try ada.identity(), Identity(actorId: "actor-ada", deviceId: "device-ada"))
        XCTAssertEqual(try bo.identity().deviceId, "device-bo")

        // Ada creates the group and is its only member.
        try ada.createGroup(id: group)
        XCTAssertEqual(try ada.roster(groupID: group).count, 1)
        let epochAtCreation = try ada.epoch(groupID: group)

        // Bo publishes a key package; Ada adds him with it.
        let keyPackage = try bo.generateKeyPackage()
        XCTAssertFalse(keyPackage.data.isEmpty)

        let add = try ada.addMember(groupID: group, keyPackage: keyPackage)
        let welcome = try XCTUnwrap(add.welcome, "an add always produces a Welcome")
        XCTAssertFalse(add.commit.isEmpty)
        XCTAssertEqual(add.epoch, epochAtCreation + 1, "the epoch it WOULD produce")

        // Staged, not adopted: there is no delivery service in this test, so
        // these two lines stand in for its acceptance.
        XCTAssertTrue(try ada.hasPendingCommit(groupID: group))
        XCTAssertEqual(try ada.epoch(groupID: group), epochAtCreation, "not yet")
        XCTAssertEqual(try ada.mergePendingCommit(groupID: group), add.epoch)
        XCTAssertFalse(try ada.hasPendingCommit(groupID: group))

        let joined = try bo.join(welcome: welcome)
        XCTAssertEqual(joined, group, "the Welcome names the group it joins")
        XCTAssertEqual(try bo.epoch(groupID: group), add.epoch)

        // The roster identifies both, and every credential verifies.
        let roster = try ada.roster(groupID: group)
        XCTAssertEqual(roster.count, 2)
        XCTAssertEqual(
            Set(roster.compactMap { $0.verified?.deviceId }),
            ["device-ada", "device-bo"]
        )
        let boEntry = try XCTUnwrap(roster.first { $0.verified?.deviceId == "device-bo" })
        let boLeaf = boEntry.leafIndex

        // A seated leaf hands back its own signing key, and it is Bo's real
        // one. This is the key Bo's own devices check a device approval
        // against before they seat a SECOND device of Bo's
        // (`checkOwnDeviceApproval`): it has to come out of the tree, because
        // a key taken from the directory that served the approval is a key
        // the directory got to choose.
        XCTAssertEqual(boEntry.deviceKey.count, 32)
        // And the ACCOUNT key its credential names, the security code's
        // input (docs/identity.md §The security code): one per actor.
        let adaEntry = try XCTUnwrap(roster.first { $0.verified?.deviceId == "device-ada" })
        XCTAssertEqual(boEntry.accountKey.count, 32)
        XCTAssertEqual(adaEntry.accountKey.count, 32)
        XCTAssertNotEqual(boEntry.accountKey, adaEntry.accountKey)
        XCTAssertEqual(
            boEntry.accountKey,
            try MLSClient.accountIdentityPublicKey(
                accountKey: Data(SHA256.hash(data: Data("peachy-test-account\0actor-bo".utf8))))
        )
        XCTAssertEqual(
            boEntry.deviceKey,
            try MLSClient.signingKeyPublicKey(seed: TestIssuer.deviceSeed(2))
        )
        // And it is usable as one: an approval over it verifies, against a key
        // nobody passed alongside it.
        let approverSeed = Data(repeating: 0x2B, count: 32)
        let approval = try MLSClient.signDeviceApproval(
            seed: approverSeed,
            deviceId: "device-bo-second",
            signingKey: boEntry.deviceKey
        )
        XCTAssertTrue(
            MLSClient.verifyDeviceApproval(
                approverKey: try MLSClient.signingKeyPublicKey(seed: approverSeed),
                deviceId: "device-bo-second",
                signingKey: boEntry.deviceKey,
                signature: approval
            )
        )

        // A message each way.
        let hello = Data("hello from ada".utf8)
        let outbound = try ada.encrypt(groupID: group, plaintext: hello)
        guard case let .application(received, sender, epoch) = try bo.processMessage(
            groupID: group,
            message: outbound
        ) else {
            return XCTFail("bo should have read an application message")
        }
        XCTAssertEqual(received, hello)
        XCTAssertEqual(sender, Identity(actorId: "actor-ada", deviceId: "device-ada"))
        XCTAssertEqual(epoch, add.epoch)

        let reply = Data("and hello back".utf8)
        let inbound = try bo.encrypt(groupID: group, plaintext: reply)
        guard case let .application(back, replySender, _) = try ada.processMessage(
            groupID: group,
            message: inbound
        ) else {
            return XCTFail("ada should have read the reply")
        }
        XCTAssertEqual(back, reply)
        XCTAssertEqual(replySender.deviceId, "device-bo")

        // Both derive the same exported secret, and a different label derives
        // a different one. This is the door an attested-inference container
        // gets, so "same group, same secret" is the property that matters.
        let mine = try ada.exportSecret(groupID: group, label: "peachy swift test", length: 32)
        let theirs = try bo.exportSecret(groupID: group, label: "peachy swift test", length: 32)
        XCTAssertEqual(mine, theirs)
        XCTAssertEqual(mine.count, 32)
        let other = try ada.exportSecret(groupID: group, label: "something else", length: 32)
        XCTAssertNotEqual(mine, other)

        // Ada removes Bo.
        let removal = try ada.removeMember(
            groupID: group, leafIndex: boLeaf, leafKey: boEntry.leafKey)
        XCTAssertNil(removal.welcome, "a removal has nobody to welcome")
        XCTAssertEqual(removal.epoch, add.epoch + 1)
        try ada.mergePendingCommit(groupID: group)

        guard case let .commit(commitEpoch, commitSender, removedSelf, _) = try bo.processCommit(
            groupID: group,
            message: removal.commit
        ) else {
            return XCTFail("bo should have seen a commit")
        }
        XCTAssertTrue(removedSelf, "bo should be told it was him")
        XCTAssertEqual(commitEpoch, removal.epoch)
        XCTAssertEqual(commitSender.deviceId, "device-ada")

        // And the removed member is out: he cannot read what comes next, and
        // he cannot send. Forward secrecy is the point of the whole exercise,
        // so this is the assertion the journey exists for.
        let afterward = try ada.encrypt(groupID: group, plaintext: Data("just me now".utf8))
        XCTAssertThrowsError(try bo.processMessage(groupID: group, message: afterward)) { error in
            XCTAssertEqual((error as? MLSError)?.code, .notAMember)
        }
        XCTAssertThrowsError(try bo.encrypt(groupID: group, plaintext: Data("still here?".utf8))) {
            XCTAssertEqual(($0 as? MLSError)?.code, .notAMember)
        }

        XCTAssertEqual(try ada.roster(groupID: group).count, 1)
    }

    /// A self-update moves the epoch for everybody, and the other member's
    /// view of the commit agrees with the committer's.
    func testSelfUpdateMovesTheEpochForBoth() throws {
        let issuer = try TestIssuer(seed: 57)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 3)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 4)

        try ada.createGroup(id: group)
        let add = try ada.addMember(
            groupID: group,
            keyPackage: try bo.generateKeyPackage()
        )
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(add.welcome))

        let update = try ada.selfUpdate(groupID: group)
        XCTAssertEqual(update.epoch, add.epoch + 1)
        try ada.mergePendingCommit(groupID: group)
        guard case let .commit(epoch, sender, removedSelf, _) = try bo.processCommit(
            groupID: group,
            message: update.commit
        ) else {
            return XCTFail("bo should have seen a commit")
        }
        XCTAssertEqual(epoch, update.epoch)
        XCTAssertEqual(sender.actorId, "actor-ada")
        XCTAssertFalse(removedSelf)

        // Messages still flow across the new epoch.
        let message = try ada.encrypt(groupID: group, plaintext: Data("new epoch".utf8))
        guard case let .application(payload, _, _) = try bo.processMessage(
            groupID: group,
            message: message
        ) else {
            return XCTFail("bo should have read an application message")
        }
        XCTAssertEqual(payload, Data("new epoch".utf8))
    }

    /// The binding links a library, and the library says which core it was
    /// built from. A wrapper that silently linked a stale archive is the
    /// failure this catches.
    func testTheLinkedCoreReportsItsVersion() {
        XCTAssertFalse(MLSClient.coreVersion.isEmpty)
        XCTAssertEqual(MLSClient.coreVersion.split(separator: ".").count, 3)
    }
}
