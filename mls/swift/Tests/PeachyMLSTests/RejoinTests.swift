// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import XCTest

@testable import PeachyMLS

/// A MONTH ASLEEP, through the wrapper the two Apple apps link
/// (docs/delivery.md §The client contract on `behind_retention`).
///
/// `mls/core/tests/rejoin.rs` holds the protocol half of this story. What that
/// one cannot hold is the binding: that three new C entry points are reachable
/// from Swift at all, that `replaceMember` hands back BOTH buffers rather than
/// dropping the Welcome on the floor, that `forgetGroup` really empties the
/// store rather than only the open map, and that `isBehind` answers a plain
/// `Bool` — including for a group this device has never held, where the honest
/// answer is "no" and a throw would make every caller write the same `catch`.
final class RejoinTests: XCTestCase {
    private let group = Data("peachy-swift-rejoin".utf8)

    /// The group's head as `member` holds it: its epoch and the SHA-256 of
    /// its send key, which is what the delivery service records. The apps
    /// take every Welcome against the head; a copy taken without one names
    /// no roster to the next Welcome's judge.
    private func head(of member: MLSClient) throws -> (epoch: UInt64, verifier: Data) {
        let key = try member.exportSecret(
            groupID: group, label: "peachy sealed-sender v1", context: group, length: 32
        )
        return (try member.epoch(groupID: group), Data(SHA256.hash(data: key)))
    }

    private func join(_ joiner: MLSClient, _ welcome: Data?, at adder: MLSClient) throws -> Data {
        let current = try head(of: adder)
        let read = try joiner.welcomeGroup(welcome: try XCTUnwrap(welcome))
        XCTAssertEqual(read.groupID, group)
        XCTAssertEqual(read.epoch, current.epoch)
        return try joiner.join(
            welcome: try XCTUnwrap(welcome), headEpoch: current.epoch, headVerifier: current.verifier
        )
    }

    /// When the device last read the group's head is the core's record of
    /// the copy: kept, read back, and gone with the group.
    func testTheHeadReadIsKeptWithTheCopy() throws {
        let issuer = try TestIssuer(seed: 92)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 23)
        XCTAssertNil(try ada.lastHeadRead(groupID: group), "a group not held")
        XCTAssertThrowsError(try ada.noteHeadRead(groupID: group, atMs: 1_000))
        try ada.createGroup(id: group)
        XCTAssertNil(try ada.lastHeadRead(groupID: group), "never read")
        try ada.noteHeadRead(groupID: group, atMs: 1_700_000_000_123)
        XCTAssertEqual(try ada.lastHeadRead(groupID: group), 1_700_000_000_123)
        try ada.forgetGroup(groupID: group)
        XCTAssertNil(try ada.lastHeadRead(groupID: group), "gone with the copy")
    }

    func testADeviceAsleepPastTheWindowIsReplacedBackIn() throws {
        let issuer = try TestIssuer(seed: 91)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 21)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 22)

        try ada.createGroup(id: group)
        let add = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try join(bo, add.welcome, at: ada)
        let seated = try head(of: ada)
        XCTAssertTrue(
            try bo.confirmHead(groupID: group, headEpoch: seated.epoch, headVerifier: seated.verifier)
        )

        // Ada keeps the group moving while Bo's phone is off. Nothing here
        // reaches Bo, which is exactly what two months of silence looks like.
        for _ in 0..<4 {
            _ = try ada.selfUpdate(groupID: group)
            try ada.mergePendingCommit(groupID: group)
        }
        let live = try ada.epoch(groupID: group)
        XCTAssertEqual(try bo.epoch(groupID: group), add.epoch, "Bo missed all of it")

        // A head moved back to the epoch Ada came through is no fork of hers;
        // to Bo, still at it, it is no head below him at all.
        XCTAssertTrue(
            try ada.headRolledBack(groupID: group, headEpoch: seated.epoch, headVerifier: seated.verifier))
        XCTAssertFalse(
            try bo.headRolledBack(groupID: group, headEpoch: seated.epoch, headVerifier: seated.verifier))

        // THE SECOND OPINION. The server claims the oldest epoch it still holds
        // is the one before Ada's head; Bo agrees he is under it and Ada does
        // not. That disagreement is the whole reason this call exists — a
        // client acting on `behind_retention` alone is one any delivery service
        // could talk into forgetting every group it has.
        XCTAssertTrue(try bo.isBehind(groupID: group, serverOldestEpoch: live - 1))
        XCTAssertFalse(try ada.isBehind(groupID: group, serverOldestEpoch: live - 1))
        // The boundary is exclusive: a device AT the oldest retained epoch
        // holds the one commit it needs to replay from.
        XCTAssertFalse(try bo.isBehind(groupID: group, serverOldestEpoch: add.epoch))
        // And a group this device has never held is not one it has fallen
        // behind — no state, nothing to be behind with, and nothing to forget.
        XCTAssertFalse(
            try bo.isBehind(groupID: Data("nobody".utf8), serverOldestEpoch: 99)
        )

        // Bo gives up locally. It is the only move he has: off the ratchet he
        // cannot sign a Remove of his own leaf that anybody would accept.
        try bo.forgetGroup(groupID: group)
        XCTAssertThrowsError(try bo.epoch(groupID: group)) { error in
            XCTAssertEqual((error as? MLSError)?.code, .noSuchGroup)
        }
        XCTAssertEqual(try ada.roster(groupID: group).count, 2, "his leaf is still in Ada's tree")

        // Ada puts him back: Remove and Add in ONE commit, which is what mints
        // the Welcome. A fresh key package, because the secrets behind the old
        // leaf are gone from Bo's device.
        let leaf = try XCTUnwrap(
            try ada.roster(groupID: group).first { $0.verified?.deviceId == "device-bo" }?.leafIndex
        )
        let replace = try ada.replaceMember(
            groupID: group,
            leafIndex: leaf,
            keyPackage: try bo.generateKeyPackage()
        )
        let welcome = try XCTUnwrap(replace.welcome, "a replace ALWAYS carries a Welcome")
        XCTAssertFalse(replace.commit.isEmpty)
        try ada.mergePendingCommit(groupID: group)
        XCTAssertEqual(try ada.roster(groupID: group).count, 2, "two members, not three")

        XCTAssertEqual(try join(bo, welcome, at: ada), group)
        XCTAssertTrue(try bo.isActive(groupID: group))
        // Who put him back, and from which device, is told once, for a line
        // in the conversation.
        XCTAssertEqual(
            try bo.takeRejoinReport(groupID: group),
            RejoinReport(readdedBy: "actor-ada", readdedByDevice: "device-ada", added: [])
        )
        XCTAssertNil(try bo.takeRejoinReport(groupID: group))
        XCTAssertEqual(try bo.epoch(groupID: group), try ada.epoch(groupID: group))

        // Sealing resumes, both ways.
        let hello = Data("welcome back".utf8)
        guard case let .application(heard, _, _) = try bo.processMessage(
            groupID: group,
            message: try ada.encrypt(groupID: group, plaintext: hello)
        ) else {
            return XCTFail("bo should have read an application message")
        }
        XCTAssertEqual(heard, hello)

        let reply = Data("what did I miss".utf8)
        guard case let .application(back, _, _) = try ada.processMessage(
            groupID: group,
            message: try bo.encrypt(groupID: group, plaintext: reply)
        ) else {
            return XCTFail("ada should have read an application message")
        }
        XCTAssertEqual(back, reply)
    }

    /// A rejoin says who left while the device was away, through the
    /// binding: the report's `departed` list, which the apps always draw.
    func testARejoinSaysWhoLeftMeanwhile() throws {
        let issuer = try TestIssuer(seed: 95)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 31)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 32)
        let cy = try issuer.client(actorId: "actor-cy", deviceId: "device-cy", tag: 33)

        try ada.createGroup(id: group)
        let addBo = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try join(bo, addBo.welcome, at: ada)
        let addCy = try ada.addMember(groupID: group, keyPackage: try cy.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.processCommit(groupID: group, message: addCy.commit)
        let seated = try head(of: ada)
        XCTAssertTrue(
            try bo.confirmHead(groupID: group, headEpoch: seated.epoch, headVerifier: seated.verifier)
        )
        try bo.forgetGroup(groupID: group)

        let cyEntry = try XCTUnwrap(
            try ada.roster(groupID: group).first { $0.verified?.deviceId == "device-cy" }
        )
        _ = try ada.removeMember(
            groupID: group, leafIndex: cyEntry.leafIndex, leafKey: cyEntry.leafKey)
        try ada.mergePendingCommit(groupID: group)
        let boLeaf = try XCTUnwrap(
            try ada.roster(groupID: group).first { $0.verified?.deviceId == "device-bo" }?.leafIndex
        )
        let replace = try ada.replaceMember(
            groupID: group, leafIndex: boLeaf, keyPackage: try bo.generateKeyPackage()
        )
        try ada.mergePendingCommit(groupID: group)
        XCTAssertEqual(try join(bo, replace.welcome, at: ada), group)
        XCTAssertEqual(
            try bo.takeRejoinReport(groupID: group),
            RejoinReport(
                readdedBy: "actor-ada", readdedByDevice: "device-ada", added: [],
                departed: ["actor-cy"])
        )
    }

    /// A device that forgot a group to rejoin it keeps the roster it last saw
    /// there, and a Welcome into the id from anybody outside that roster is
    /// drawn against it: through the binding, the report
    /// `mls/core/tests/rejoin_roster.rs` holds. A person who left on purpose
    /// drops the roster and takes the next Welcome as a new invitation.
    func testAWelcomeFromOutsideTheRosterIsDrawnAfterAForget() throws {
        let issuer = try TestIssuer(seed: 94)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 28)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 29)
        let eve = try issuer.client(actorId: "actor-eve", deviceId: "device-eve", tag: 30)

        try ada.createGroup(id: group)
        let add = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try join(bo, add.welcome, at: ada)
        try bo.forgetGroup(groupID: group)

        // Eve founds her own group under the same id and adds Bo, past the
        // epoch Bo held there: a Welcome at or below it is refused as stale.
        // Taken, and drawn as Eve's.
        try eve.createGroup(id: group)
        for _ in 0..<2 {
            _ = try eve.selfUpdate(groupID: group)
            try eve.mergePendingCommit(groupID: group)
        }
        let impostor = try eve.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try eve.mergePendingCommit(groupID: group)
        XCTAssertEqual(try bo.join(welcome: try XCTUnwrap(impostor.welcome)), group)
        XCTAssertEqual(
            try bo.takeRejoinReport(groupID: group),
            RejoinReport(
                readdedBy: "actor-eve", readdedByDevice: "device-eve",
                added: ["actor-eve"], departed: ["actor-ada"]
            )
        )
        XCTAssertNil(try bo.takeRejoinReport(groupID: group))

        // Bo meant to leave: the roster goes, and Eve's next Welcome is an
        // invitation like any other.
        try bo.forgetGroup(groupID: group)
        try bo.forgetRememberedRoster(groupID: group)
        let leaf = try XCTUnwrap(
            try eve.roster(groupID: group).first { $0.verified?.deviceId == "device-bo" }?.leafIndex
        )
        let again = try eve.replaceMember(
            groupID: group, leafIndex: leaf, keyPackage: try bo.generateKeyPackage()
        )
        try eve.mergePendingCommit(groupID: group)
        XCTAssertEqual(try bo.join(welcome: try XCTUnwrap(again.welcome)), group)
        XCTAssertNil(try bo.takeRejoinReport(groupID: group), "an invitation, not a rejoin")
    }

    /// A replace is not a door into somebody else's leaf. The core refuses one
    /// whose key package names a different actor, and this asserts the refusal
    /// crosses the binding as a thrown `MLSError` rather than as a status code
    /// nobody read.
    func testAReplaceCannotHandALeafToSomebodyElse() throws {
        let issuer = try TestIssuer(seed: 92)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 23)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 24)
        let cy = try issuer.client(actorId: "actor-cy", deviceId: "device-cy", tag: 25)

        try ada.createGroup(id: group)
        let add = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(add.welcome))

        let boLeaf = try XCTUnwrap(
            try ada.roster(groupID: group).first { $0.verified?.deviceId == "device-bo" }?.leafIndex
        )
        XCTAssertThrowsError(
            try ada.replaceMember(
                groupID: group,
                leafIndex: boLeaf,
                keyPackage: try cy.generateKeyPackage()
            )
        )
        // Nothing was staged by the refusal, so the group is untouched and the
        // next ordinary commit still works.
        XCTAssertFalse(try ada.hasPendingCommit(groupID: group))
        XCTAssertEqual(try ada.epoch(groupID: group), add.epoch)
    }

    /// A COMMIT THIS DEVICE CANNOT APPLY (docs/delivery.md §A
    /// commit this device cannot apply), through the wrapper: only a commit
    /// that opened and verified and was then refused strands, so a commit
    /// that never opened does not, at Bo's epoch or above it; neither does
    /// one he has already left, anything that is not a commit, or a group he
    /// does not hold. `mls/core/tests/stranded.rs` is the protocol half.
    func testCommitStrandsTellsAWedgeFromADuplicate() throws {
        let issuer = try TestIssuer(seed: 93)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 26)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 27)

        try ada.createGroup(id: group)
        let add = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(add.welcome))

        let first = try ada.selfUpdate(groupID: group)
        try ada.mergePendingCommit(groupID: group)
        let second = try ada.selfUpdate(groupID: group)
        try ada.mergePendingCommit(groupID: group)

        XCTAssertFalse(try bo.commitStrands(groupID: group, message: first.commit))
        XCTAssertFalse(try bo.commitStrands(groupID: group, message: second.commit))
        XCTAssertThrowsError(try bo.processCommit(groupID: group, message: second.commit))
        XCTAssertFalse(try bo.commitStrands(groupID: group, message: second.commit))
        XCTAssertFalse(try bo.commitStrands(groupID: group, message: add.commit))
        _ = try bo.processCommit(groupID: group, message: first.commit)
        XCTAssertFalse(try bo.commitStrands(groupID: group, message: first.commit))
        let said = try ada.encrypt(groupID: group, plaintext: Data("hi".utf8))
        XCTAssertFalse(try bo.commitStrands(groupID: group, message: said))
        XCTAssertFalse(try bo.commitStrands(groupID: group, message: Data("garbage".utf8)))
        XCTAssertFalse(
            try bo.commitStrands(groupID: Data("nobody".utf8), message: second.commit)
        )

        // A signed seat ask is taken in once.
        let proof = try bo.signJoinRequest(groupID: group)
        XCTAssertTrue(try ada.firstSightOfJoinRequest(groupID: group, proof: proof))
        XCTAssertFalse(try ada.firstSightOfJoinRequest(groupID: group, proof: proof))
        XCTAssertNil(try bo.contestedWelcomeGroupID())
    }
}
