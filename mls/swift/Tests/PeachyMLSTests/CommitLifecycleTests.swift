// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// Stage → submit → merge-or-clear, and what closing a client means.
///
/// The Rust twin is `mls/core/tests/commit_race.rs`. This one exists because
/// the failure it rules out is a Swift-shaped one: `addMember` returns a
/// `CommitBundle` and an iOS caller has to decide what to do with it, and the
/// wrong decision — adopt it now, ask the server later — produces no error, no
/// crash and no log line. It produces a device that is quietly alone in a group
/// of its own, still reporting `isActive`, still encrypting, read by nobody.
final class CommitLifecycleTests: XCTestCase {
    private let group = Data("peachy-lifecycle".utf8)

    /// Two members commit at the same epoch. The delivery service takes one and
    /// refuses the other; the loser drops its branch and follows the winner.
    func testTheLoserOfARaceDropsItsBranchAndFollowsTheWinner() throws {
        let issuer = try TestIssuer(seed: 71)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 11)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 12)
        let cy = try issuer.client(actorId: "actor-cy", deviceId: "device-cy", tag: 13)

        try ada.createGroup(id: group)
        let seeded = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(seeded.welcome))
        XCTAssertEqual(try ada.epoch(groupID: group), 1)
        XCTAssertEqual(try bo.epoch(groupID: group), 1)

        // Both build a commit at epoch 1. Ada's reaches the server first.
        let adaCommit = try ada.selfUpdate(groupID: group)
        let boCommit = try bo.addMember(groupID: group, keyPackage: try cy.generateKeyPackage())
        XCTAssertEqual(adaCommit.epoch, 2)
        XCTAssertEqual(boCommit.epoch, 2, "both were built to produce the same epoch")
        XCTAssertTrue(try bo.hasPendingCommit(groupID: group))

        try ada.mergePendingCommit(groupID: group)

        // Bo is refused. Dropping the staged commit is what makes the next line
        // possible at all: the library refuses to process an incoming commit
        // over a staged one, and merging it would strand Bo forever.
        try bo.clearPendingCommit(groupID: group)
        XCTAssertFalse(try bo.hasPendingCommit(groupID: group))
        XCTAssertEqual(try bo.epoch(groupID: group), 1, "still where he started")

        guard case .commit = try bo.processCommit(groupID: group, message: adaCommit.commit) else {
            return XCTFail("bo should have seen ada's commit")
        }
        XCTAssertEqual(try bo.epoch(groupID: group), 2, "and now where the group is")

        // The proof they are one group again: a message still crosses.
        let hello = try ada.encrypt(groupID: group, plaintext: Data("after the race".utf8))
        guard case let .application(heard, _, _) = try bo.processMessage(groupID: group, message: hello)
        else {
            return XCTFail("bo should have read an application message")
        }
        XCTAssertEqual(heard, Data("after the race".utf8))

        // And Bo can try again, built at the epoch the group actually reached.
        let retry = try bo.addMember(groupID: group, keyPackage: try cy.generateKeyPackage())
        XCTAssertEqual(retry.epoch, 3)
        try bo.mergePendingCommit(groupID: group)
        _ = try ada.processCommit(groupID: group, message: retry.commit)
        XCTAssertEqual(try cy.join(welcome: try XCTUnwrap(retry.welcome)), group)
        XCTAssertEqual(try cy.roster(groupID: group).count, 3)
    }

    /// Merging nothing is an error; clearing nothing is not. The asymmetry is
    /// deliberate: an error path unwinding should not have to know how far it
    /// got, and a caller that merges with nothing staged has lost track of its
    /// own state and should hear so rather than be handed an epoch.
    func testMergingNothingThrowsAndClearingNothingDoesNot() throws {
        let issuer = try TestIssuer(seed: 72)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 14)

        try ada.createGroup(id: group)
        XCTAssertFalse(try ada.hasPendingCommit(groupID: group))
        XCTAssertNoThrow(try ada.clearPendingCommit(groupID: group))
        XCTAssertThrowsError(try ada.mergePendingCommit(groupID: group)) { error in
            XCTAssertEqual((error as? MLSError)?.code, .invalidArgument)
        }
    }

    /// An ORPHAN Welcome — one from a commit the delivery service refused —
    /// reaching a device already in that group is refused, and the live group
    /// survives it.
    ///
    /// This is the shape that matters, and it is not the same as a plain
    /// replay: a replay names a key package that is already spent, so it dies
    /// inside the library before the group id is ever read. An orphan names a
    /// FRESH one, so it opens far enough to say which group it is for — and
    /// without a guard it would tear down a live group and rebuild it from a
    /// snapshot of a branch nobody took. The loser of a race sends one of these
    /// every time somebody adds a member and loses.
    func testAnOrphanWelcomeIsRefusedAndTheLiveGroupSurvives() throws {
        let issuer = try TestIssuer(seed: 73)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 15)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 16)
        let cy = try issuer.client(actorId: "actor-cy", deviceId: "device-cy", tag: 18)

        try ada.createGroup(id: group)
        let seeded = try ada.addMember(groupID: group, keyPackage: try cy.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try cy.join(welcome: try XCTUnwrap(seeded.welcome))

        // Ada and Cy both add Bo at epoch 1, from two of his key packages.
        let byAda = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        let byCy = try cy.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())

        // Ada wins. Bo joins her group; Cy drops his branch and follows.
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(byAda.welcome))
        try cy.clearPendingCommit(groupID: group)
        _ = try cy.processCommit(groupID: group, message: byAda.commit)

        // Cy's orphan Welcome turns up late.
        XCTAssertThrowsError(try bo.join(welcome: try XCTUnwrap(byCy.welcome))) { error in
            XCTAssertEqual((error as? MLSError)?.code, .alreadyAMember)
        }

        // Untouched: Bo can still read the group he was already in.
        let hello = try ada.encrypt(groupID: group, plaintext: Data("still here".utf8))
        guard case let .application(heard, _, _) = try bo.processMessage(groupID: group, message: hello)
        else {
            return XCTFail("the live group should have survived the orphan")
        }
        XCTAssertEqual(heard, Data("still here".utf8))
    }

    /// `close()` exists so that a caller can say WHEN the SQLite file is
    /// released — which `deinit` cannot, since ARC frees when the last
    /// reference goes rather than when you stopped wanting one. It is what
    /// `destroyStore(at:)` needs to have happened first.
    func testCloseIsIdempotentAndEveryCallAfterItThrows() throws {
        let issuer = try TestIssuer(seed: 74)
        let store = FileManager.default.temporaryDirectory
            .appendingPathComponent("close-\(UUID().uuidString).sqlite")
        let ada = try issuer.client(
            actorId: "actor-ada", deviceId: "device-ada", tag: 17, storePath: store.path)

        try ada.createGroup(id: group)
        XCTAssertTrue(ada.isOpen)

        ada.close()
        XCTAssertFalse(ada.isOpen)
        ada.close()  // idempotent, like Kotlin's

        XCTAssertThrowsError(try ada.groupIDs()) { error in
            XCTAssertEqual((error as? MLSError)?.code, .closed)
        }
        XCTAssertThrowsError(try ada.epoch(groupID: group)) { error in
            XCTAssertEqual((error as? MLSError)?.code, .closed)
        }

        // Closed first, then unlinked: the order `destroyStore` documents.
        MLSClient.destroyStore(at: store)
        for suffix in ["", "-wal", "-shm"] {
            XCTAssertFalse(
                FileManager.default.fileExists(atPath: store.path + suffix),
                "\(suffix.isEmpty ? "the database" : suffix) should be gone"
            )
        }
    }
}
