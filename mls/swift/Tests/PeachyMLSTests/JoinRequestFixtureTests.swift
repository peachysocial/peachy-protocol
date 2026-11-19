// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// The golden join-request fixture, replayed through the C door from Swift.
///
/// `mls/fixtures/join-request.json` pins what a device signs to ask for a seat
/// in a group and what an admitting device decides about it
/// (`mls/core/src/join_request.rs`). The other replays are
/// `mls/core/tests/join_request_fixture.rs`,
/// `mls/wasm/tests/node/join-request.test.mjs` and
/// the Android binding's `JoinRequestFixtureTest` (not in this repository). It goes
/// through the same fixture door as the other tables (`RulesFixture.evaluate`),
/// told apart by each case's `kind`, and also drives the product doors an app
/// calls: ``MLSClient/signJoinRequest(groupID:)`` and
/// ``MLSClient/verifyJoinRequest(groupID:actorId:deviceId:proof:keyPackage:pendingActors:)``.
final class JoinRequestFixtureTests: XCTestCase {
    private let formatVersion = 1
    private let calls = ["statement", "sign", "verify", "roundTrip"]

    private static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()  // …/mls/swift/Tests
            .deletingLastPathComponent()  // …/mls/swift
            .deletingLastPathComponent()  // …/mls
            .appendingPathComponent("fixtures/join-request.json")
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
        XCTAssertGreaterThanOrEqual(try cases().count, 28, "the fixture shrank or stopped parsing")
        for testCase in try cases() {
            let id = testCase["id"] ?? "<no id>"
            XCTAssertEqual(testCase["kind"] as? String, "join_request", "case \(id) has no kind")
            XCTAssertNotEqual(
                testCase["expect"] == nil, testCase["expectError"] == nil,
                "case \(id) needs exactly one of `expect` and `expectError`"
            )
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
            if let expectedError = testCase["expectError"] as? String {
                do {
                    let answered = try RulesFixture.evaluate(case: testCase)
                    failures.append("  \(id)\n    expected a refusal, got \(answered)")
                } catch {
                    let message = String(describing: error)
                    if !message.contains(expectedError) {
                        failures.append("  \(id)\n    expected a refusal naming \(expectedError), got \(message)")
                    }
                }
                continue
            }
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
            "\(failures.count) of \(all.count) join-request cases disagree:\n"
                + failures.joined(separator: "\n")
        )
    }

    func testEveryCallAndEveryVerdictIsReachedWithItsTrueNumber() throws {
        let all = try cases()
        let reached = Set(all.compactMap { $0["call"] as? String })
        for call in calls {
            XCTAssertTrue(reached.contains(call), "no case calls \(call)")
        }
        var verdicts = Set<JoinRequestVerdict>()
        for testCase in all {
            guard let expect = testCase["expect"] as? [String: Any],
                  let name = expect["verdict"] as? String,
                  let code = expect["verdictCode"] as? Int
            else { continue }
            let verdict = try XCTUnwrap(JoinRequestVerdict(rawValue: UInt32(code)))
            XCTAssertEqual(verdict.name, name, "case \(testCase["id"] ?? "") names the wrong number")
            verdicts.insert(verdict)
        }
        XCTAssertEqual(verdicts, Set(JoinRequestVerdict.allCases))
    }

    func testTheClientDoorsSignAndVerifyAndAMemberCannotSignForSomebodyElse() throws {
        let issuer = try TestIssuer(seed: 7)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada-phone", tag: 0x11)
        let mallory = try issuer.client(actorId: "actor-mallory", deviceId: "device-mallory-phone", tag: 0x22)
        let bob = try issuer.client(actorId: "actor-bob", deviceId: "device-bob-phone", tag: 0x33)
        let room = Data("room-1".utf8)
        let adaPackage = try ada.generateKeyPackage().data

        let honest = try ada.signJoinRequest(groupID: room)
        XCTAssertEqual(honest.count, 89)
        XCTAssertEqual(
            try bob.verifyJoinRequest(
                groupID: room, actorId: "actor-ada", deviceId: "device-ada-phone",
                proof: honest, keyPackage: adaPackage, pendingActors: ["actor-ada"]
            ),
            .accepted
        )
        // The pending list crosses the door framed: the asker anywhere in it
        // counts, and a neighbor never runs into the asker's id.
        XCTAssertEqual(
            try bob.verifyJoinRequest(
                groupID: room, actorId: "actor-ada", deviceId: "device-ada-phone",
                proof: honest, keyPackage: adaPackage, pendingActors: ["actor-zed", "actor-ada", "actor-yan"]
            ),
            .accepted
        )
        let forged = try mallory.signJoinRequest(groupID: room)
        XCTAssertEqual(
            try bob.verifyJoinRequest(
                groupID: room, actorId: "actor-ada", deviceId: "device-ada-phone",
                proof: forged, keyPackage: adaPackage, pendingActors: ["actor-ada"]
            ),
            .badSignature
        )
        XCTAssertEqual(
            try bob.verifyJoinRequest(
                groupID: Data("room-2".utf8), actorId: "actor-ada", deviceId: "device-ada-phone",
                proof: honest, keyPackage: adaPackage, pendingActors: ["actor-ada"]
            ),
            .badSignature
        )
        XCTAssertEqual(
            try bob.verifyJoinRequest(
                groupID: room, actorId: "actor-ada", deviceId: "device-ada-phone",
                proof: Data(), keyPackage: adaPackage, pendingActors: ["actor-ada"]
            ),
            .malformed
        )
        XCTAssertEqual(
            try bob.verifyJoinRequest(
                groupID: room, actorId: "actor-ada", deviceId: "device-ada-phone",
                proof: honest, keyPackage: Data([1, 2]), pendingActors: ["actor-ada"]
            ),
            .credentialRejected
        )
        // Bob holds no copy of the room and is not adding Ada: a signed ask
        // proves who is asking, never that they belong.
        XCTAssertEqual(
            try bob.verifyJoinRequest(
                groupID: room, actorId: "actor-ada", deviceId: "device-ada-phone",
                proof: honest, keyPackage: adaPackage, pendingActors: []
            ),
            .notAMember
        )
        // A person Bob admits by his own rule (a link, an open group's join
        // inbox): every check but membership.
        XCTAssertEqual(
            try bob.verifyAdmittedJoinRequest(
                groupID: room, actorId: "actor-ada", deviceId: "device-ada-phone",
                proof: honest, keyPackage: adaPackage
            ),
            .accepted
        )
        XCTAssertEqual(
            try bob.verifyAdmittedJoinRequest(
                groupID: room, actorId: "actor-ada", deviceId: "device-ada-phone",
                proof: forged, keyPackage: adaPackage
            ),
            .badSignature
        )
    }
}
