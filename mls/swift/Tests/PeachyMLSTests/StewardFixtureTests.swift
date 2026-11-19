// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// The golden steward fixture, replayed through the C door from Swift.
///
/// `mls/fixtures/steward.json` pins the steward key's statements, the veto
/// frame and how it nests around a carried frame, the commit MAC, the sealed
/// stamp, the head log copy, the repair notice and the meta's `stw.k`
/// (`mls/core/src/steward.rs`). The other replays are
/// `mls/core/tests/steward_fixture.rs`, `mls/wasm/tests/node/steward.test.mjs`
/// and the Android binding's `StewardFixtureTest` (not in this repository). It goes
/// through the same fixture door as the other tables (`RulesFixture.evaluate`),
/// told apart by each case's `kind`, and also drives the binding's steward
/// doors: the check after a commit, and the hold, inert in a group whose meta
/// names no steward key.
final class StewardFixtureTests: XCTestCase {
    private let formatVersion = 1
    private let calls = [
        "constants", "public_key", "statement", "wrap_veto", "split", "verify_veto", "mac",
        "seal_stamp", "open_stamp", "seal_log_copy", "open_log_copy", "repair_notice", "meta_key",
    ]

    private static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()  // …/mls/swift/Tests
            .deletingLastPathComponent()  // …/mls/swift
            .deletingLastPathComponent()  // …/mls
            .appendingPathComponent("fixtures/steward.json")
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
        XCTAssertGreaterThanOrEqual(all.count, 30, "the fixture shrank or stopped parsing")
        for testCase in all {
            let id = testCase["id"] ?? "<no id>"
            XCTAssertEqual(testCase["kind"] as? String, "steward", "case \(id) has no kind")
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
            "\(failures.count) of \(all.count) steward cases disagree:\n"
                + failures.joined(separator: "\n")
        )
    }

    func testTheClientDoorsCheckAStampAndHoldNothingUnenrolled() throws {
        let issuer = try TestIssuer(seed: 7)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 0x11)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 0x22)
        let group = Data("steward-room".utf8)
        try ada.createGroup(id: group)
        let addBo = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        _ = try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(addBo.welcome))

        // A stamp that is not this epoch's is unopened: an alert, and the
        // commit still merges (this build refuses nothing for it).
        let update = try ada.selfUpdate(groupID: group)
        _ = try ada.mergePendingCommit(groupID: group)
        try bo.noteCommitStamp(groupID: group, stamp: Data(repeating: 1, count: 125))
        _ = try bo.processCommit(groupID: group, message: update.commit)
        let check = try XCTUnwrap(try bo.takeCommitCheck(groupID: group))
        let parsed = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(check.utf8)) as? [String: Any]
        )
        XCTAssertEqual(parsed["stamp"] as? String, "unopened")
        XCTAssertNil(try bo.takeCommitCheck(groupID: group), "taken once")

        XCTAssertFalse(try bo.enterHold(groupID: group, reason: 1), "no steward key, no hold")
        XCTAssertNil(try bo.groupHold(groupID: group))
        XCTAssertThrowsError(try bo.enterHold(groupID: group, reason: 9))
        try bo.releaseHold(groupID: group)
        XCTAssertEqual(try bo.judgeVeto(groupID: group, entry: update.commit), 0)
        XCTAssertEqual(
            try bo.checkRepairNotice(
                groupID: group, sender: "actor-ada", wire: Data(#"{"peachy":"hello","v":1}"#.utf8)
            ),
            2
        )
        XCTAssertThrowsError(try bo.openFetchedCommit(groupID: group, sealed: Data(count: 40)))
    }
}
