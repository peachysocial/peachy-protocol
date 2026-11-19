// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// The golden client-refusals fixture, replayed through the C door from Swift.
///
/// `mls/fixtures/client-refusals.json` lists every refusal the delivery
/// service can switch on, with this build's compiled default, and pins the
/// one-way rule (`mls/core/src/client_refusals.rs`). The other replays are
/// `mls/core/tests/client_refusals_fixture.rs`,
/// `mls/wasm/tests/node/client-refusals.test.mjs` and
/// the Android binding's `ClientRefusalsFixtureTest` (not in this repository). It
/// also drives the product door an app calls:
/// ``MLSClient/adoptClientRefusals(_:)``.
final class ClientRefusalsFixtureTests: XCTestCase {
    private static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()  // …/mls/swift/Tests
            .deletingLastPathComponent()  // …/mls/swift
            .deletingLastPathComponent()  // …/mls
            .appendingPathComponent("fixtures/client-refusals.json")
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

    func testEveryCaseGetsTheVerdictItExpectsThroughTheCDoor() throws {
        let root = try root()
        XCTAssertEqual(root["version"] as? Int, 1)
        let all = try XCTUnwrap(root["cases"] as? [[String: Any]])
        let reached = Set(all.compactMap { $0["call"] as? String })
        for call in ["table", "ratchet", "on"] {
            XCTAssertTrue(reached.contains(call), "no case calls \(call)")
        }
        var failures: [String] = []
        for testCase in all {
            let id = testCase["id"] as? String ?? "<no id>"
            XCTAssertEqual(testCase["kind"] as? String, "client_refusals", "case \(id)")
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
            "\(failures.count) client-refusals cases disagree:\n" + failures.joined(separator: "\n")
        )
    }

    /// `signed_revocations`, switched on through the client door, keeps a
    /// sibling leaf the server named, at once, and after a list without it.
    func testTheClientDoorSwitchesSignedRevocationsOnForGood() throws {
        let issuer = try TestIssuer(seed: 7)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 0x22)
        let laptop = try issuer.client(actorId: "actor-ada", deviceId: "device-ada-laptop", tag: 0x11)
        let phone = try issuer.client(actorId: "actor-ada", deviceId: "device-ada-phone", tag: 0x12)
        let group = Data("client-refusals-room".utf8)
        try bo.createGroup(id: group)
        for joiner in [laptop, phone] {
            let bundle = try bo.addMember(groupID: group, keyPackage: try joiner.generateKeyPackage())
            _ = try bo.mergePendingCommit(groupID: group)
            XCTAssertEqual(try joiner.join(welcome: try XCTUnwrap(bundle.welcome)), group)
        }
        let phoneLeaf: UInt32 = 2
        let compiled = try XCTUnwrap(
            (try root()["refusals"] as? [[String: Any]])?
                .first { $0["name"] as? String == "signed_revocations" }?["compiledDefault"] as? Bool)
        XCTAssertEqual(
            try bo.staleLeafRemovable(groupID: group, leafIndex: phoneLeaf, revocation: Data()), !compiled)
        try bo.adoptClientRefusals(["no_such_refusal"])
        XCTAssertEqual(
            try bo.staleLeafRemovable(groupID: group, leafIndex: phoneLeaf, revocation: Data()), !compiled)
        try bo.adoptClientRefusals(["own_seat_check", "signed_revocations"])
        XCTAssertFalse(try bo.staleLeafRemovable(groupID: group, leafIndex: phoneLeaf, revocation: Data()))
        try bo.adoptClientRefusals([])
        XCTAssertFalse(try bo.staleLeafRemovable(groupID: group, leafIndex: phoneLeaf, revocation: Data()))
    }

    /// `removeStaleLeaf` stages only what the judge allows: never this
    /// device's own leaf, a sibling leaf while `signed_revocations` is off,
    /// and nothing once it is on.
    func testRemoveStaleLeafStagesOnlyWhatTheJudgeAllows() throws {
        let issuer = try TestIssuer(seed: 7)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 0x22)
        let laptop = try issuer.client(actorId: "actor-ada", deviceId: "device-ada-laptop", tag: 0x11)
        let phone = try issuer.client(actorId: "actor-ada", deviceId: "device-ada-phone", tag: 0x12)
        let group = Data("remove-stale-leaf-room".utf8)
        try bo.createGroup(id: group)
        for joiner in [laptop, phone] {
            let bundle = try bo.addMember(groupID: group, keyPackage: try joiner.generateKeyPackage())
            _ = try bo.mergePendingCommit(groupID: group)
            XCTAssertEqual(try joiner.join(welcome: try XCTUnwrap(bundle.welcome)), group)
        }
        let key = { (leaf: UInt32) in
            try XCTUnwrap(try bo.roster(groupID: group).first { $0.leafIndex == leaf }).leafKey
        }
        XCTAssertNil(
            try bo.removeStaleLeaf(groupID: group, leafIndex: 0, leafKey: try key(0), revocation: Data()))
        let compiled = try XCTUnwrap(
            (try root()["refusals"] as? [[String: Any]])?
                .first { $0["name"] as? String == "signed_revocations" }?["compiledDefault"] as? Bool)
        let phoneLeaf: UInt32 = 2
        let staged = try bo.removeStaleLeaf(
            groupID: group, leafIndex: phoneLeaf, leafKey: try key(phoneLeaf), revocation: Data())
        XCTAssertEqual(staged != nil, !compiled)
        if let staged {
            XCTAssertFalse(staged.commit.isEmpty)
            try bo.clearPendingCommit(groupID: group)
        }
        try bo.adoptClientRefusals(["signed_revocations"])
        XCTAssertNil(
            try bo.removeStaleLeaf(
                groupID: group, leafIndex: phoneLeaf, leafKey: try key(phoneLeaf), revocation: Data()))
    }
}
