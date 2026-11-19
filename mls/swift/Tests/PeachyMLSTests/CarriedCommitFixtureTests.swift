// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// The golden carried-commit fixture, replayed through the C door from Swift.
///
/// `mls/fixtures/carried-commit.json` pins the carried commit
/// (`mls/core/src/carried_commit.rs`): its bytes, what a reader accepts and
/// refuses, and the frame's constants. The
/// other replays are `mls/core/tests/carried_commit_fixture.rs`,
/// `mls/wasm/tests/node/carried-commit.test.mjs` and
/// the Android binding's `CarriedCommitFixtureTest` (not in this repository). It
/// goes through the same fixture door as the other tables
/// (`RulesFixture.evaluate`), told apart by each case's `kind`, and also drives
/// the leave doors an app calls: ``MLSClient/beginLeave(groupId:)`` keeps a
/// stub, ``MLSClient/followLeave(groupId:message:)`` proposes again after a
/// commit that took the epoch, and the commit that lands ends the leave.
final class CarriedCommitFixtureTests: XCTestCase {
    private let formatVersion = 1
    private let calls = ["constants", "carry", "split"]

    private static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()  // …/mls/swift/Tests
            .deletingLastPathComponent()  // …/mls/swift
            .deletingLastPathComponent()  // …/mls
            .appendingPathComponent("fixtures/carried-commit.json")
    }

    private func root() throws -> [String: Any] {
        let url = Self.fixtureURL
        guard let data = try? Data(contentsOf: url),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw RulesFixture.Failure.fixtureUnreadable(url.path)
        }
        return root
    }

    private func cases() throws -> [[String: Any]] {
        try XCTUnwrap(try root()["cases"] as? [[String: Any]], "`cases` is an array of objects")
    }

    func testTheFixtureIsTheFormatThisBuildReads() throws {
        XCTAssertEqual(try root()["version"] as? Int, formatVersion)
        let all = try cases()
        XCTAssertGreaterThanOrEqual(all.count, 20, "the fixture shrank or stopped parsing")
        for testCase in all {
            let id = testCase["id"] ?? "<no id>"
            XCTAssertEqual(testCase["kind"] as? String, "carried_commit", "case \(id) has no kind")
            XCTAssertNotNil(testCase["expect"] as? [String: Any], "case \(id) has no `expect`")
        }
        let reached = Set(all.compactMap { $0["call"] as? String })
        for call in calls {
            XCTAssertTrue(reached.contains(call), "no case calls \(call)")
        }
    }

    func testEveryCaseGetsTheVerdictItExpectsThroughTheCDoor() throws {
        var failures: [String] = []
        var ids = Set<String>()
        let all = try cases()
        for testCase in all {
            let id = testCase["id"] as? String ?? "<no id>"
            XCTAssertFalse(ids.contains(id), "two cases share the id \(id)")
            ids.insert(id)
            let expected = try XCTUnwrap(testCase["expect"] as? [String: Any])
            do {
                let text = try RulesFixture.evaluate(case: testCase)
                let verdict = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any]
                )
                if NSDictionary(dictionary: verdict) != NSDictionary(dictionary: expected) {
                    failures.append("  \(id)\n    expected \(expected)\n    actual   \(verdict)")
                }
            } catch {
                failures.append("  \(id)\n    refused: \(error)")
            }
        }
        XCTAssertTrue(
            failures.isEmpty,
            "\(failures.count) of \(all.count) carried-commit cases disagree:\n"
                + failures.joined(separator: "\n")
        )
    }

    func testTheClientDoorsKeepALeaveProposingUntilItTakes() throws {
        let issuer = try TestIssuer(seed: 7)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 0x11)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 0x22)
        let cy = try issuer.client(actorId: "actor-cy", deviceId: "device-cy", tag: 0x33)
        let group = Data("carried-commit-room".utf8)
        try ada.createGroup(id: group)

        let addBo = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        _ = try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(addBo.welcome))
        let addCy = try ada.addMember(groupID: group, keyPackage: try cy.generateKeyPackage())
        _ = try ada.mergePendingCommit(groupID: group)
        _ = try bo.processCommit(groupID: group, message: addCy.commit)
        _ = try cy.join(welcome: try XCTUnwrap(addCy.welcome))

        let first = try bo.beginLeave(groupId: group)
        XCTAssertEqual(first.count, 1, "one proposal for Bo's one leaf")
        XCTAssertTrue(try bo.isLeaving(groupId: group))
        XCTAssertEqual(try bo.groupIDs().count, 0, "the stub is in no listing")
        XCTAssertEqual(try bo.beginLeave(groupId: group).count, 0, "a second call proposes nothing")
        XCTAssertEqual(
            try bo.leaveRecipients(groupId: group).map(\.deviceId).sorted(),
            ["device-ada", "device-bo", "device-cy"],
            "the leave is still addressed to every leaf"
        )

        // Ada's update takes the epoch first; Bo's stub proposes again.
        let update = try ada.selfUpdate(groupID: group)
        _ = try ada.mergePendingCommit(groupID: group)
        _ = try cy.processCommit(groupID: group, message: update.commit)
        let again = try bo.followLeave(groupId: group, message: update.commit)
        XCTAssertEqual(again.count, 1, "proposed again at the new epoch")

        guard case .proposalQueued = try cy.processMessage(groupID: group, message: again[0]) else {
            return XCTFail("the second proposal did not queue")
        }
        // Every member queues the proposal itself as well; the carried commit
        // brings it to any member it never reached.
        guard case .proposalQueued = try ada.processMessage(groupID: group, message: again[0]) else {
            return XCTFail("Ada did not queue the second proposal")
        }
        let leave = try XCTUnwrap(try cy.commitProposedLeaves(groupID: group))
        _ = try cy.mergePendingCommit(groupID: group)
        guard case let .commit(_, _, _, left) = try ada.processCommit(groupID: group, message: leave.commit)
        else {
            return XCTFail("the leave did not read as a commit")
        }
        XCTAssertEqual(left, ["actor-bo"])

        XCTAssertEqual(try bo.followLeave(groupId: group, message: leave.commit).count, 0)
        XCTAssertFalse(try bo.isLeaving(groupId: group), "the leave took")
    }
}
