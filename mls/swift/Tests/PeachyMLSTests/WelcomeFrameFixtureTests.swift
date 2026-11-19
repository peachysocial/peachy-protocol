// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// The golden Welcome-frame fixture, replayed through the C door from Swift.
///
/// `mls/fixtures/welcome-frame.json` pins the padded Welcome frame
/// (`mls/core/src/welcome_frame.rs`): its bytes, its target's rounding, what a
/// reader accepts and refuses: every add and reseat is sent framed. The other replays are
/// `mls/core/tests/welcome_frame_fixture.rs`,
/// `mls/wasm/tests/node/welcome-frame.test.mjs` and
/// the Android binding's `WelcomeFrameFixtureTest` (not in this repository). It goes
/// through the same fixture door as the other tables (`RulesFixture.evaluate`),
/// told apart by each case's `kind`, and also drives the product door an app
/// calls: ``MLSClient/join(welcome:)`` with a framed real Welcome.
final class WelcomeFrameFixtureTests: XCTestCase {
    private let formatVersion = 1
    private let calls = ["constants", "frame", "paddedLen", "unframe", "sealGap", "openGap"]

    private static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()  // …/mls/swift/Tests
            .deletingLastPathComponent()  // …/mls/swift
            .deletingLastPathComponent()  // …/mls
            .appendingPathComponent("fixtures/welcome-frame.json")
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
            XCTAssertEqual(testCase["kind"] as? String, "welcome_frame", "case \(id) has no kind")
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
            "\(failures.count) of \(all.count) welcome-frame cases disagree:\n"
                + failures.joined(separator: "\n")
        )
    }

    func testTheClientDoorSeatsAJoinerFromAFramedRealWelcome() throws {
        let issuer = try TestIssuer(seed: 7)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 0x11)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 0x22)
        let group = Data("welcome-frame-room".utf8)
        try ada.createGroup(id: group)
        let bundle = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        _ = try ada.mergePendingCommit(groupID: group)
        let sent = try XCTUnwrap(bundle.welcome)
        // Bo's package reads the frame, so the Welcome comes framed; take the
        // raw Welcome out of it and frame it again with fill of our own.
        XCTAssertEqual(Array(sent.prefix(4)), [0xff, 0x50, 0x57, 0x01])
        let unframed = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(
                    try RulesFixture.evaluate(case: [
                        "kind": "welcome_frame",
                        "call": "unframe",
                        "bytesHex": sent.map { String(format: "%02x", $0) }.joined(),
                    ]).utf8)) as? [String: Any]
        )
        XCTAssertEqual(unframed["accepted"] as? Bool, true)
        let welcome = try XCTUnwrap(Self.bytes(hex: try XCTUnwrap(unframed["welcomeHex"] as? String)))

        let answer = try RulesFixture.evaluate(case: [
            "kind": "welcome_frame",
            "call": "frame",
            "welcomeHex": welcome.map { String(format: "%02x", $0) }.joined(),
            "paddedLen": welcome.count + 1024,
        ])
        let verdict = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(answer.utf8)) as? [String: Any]
        )
        let framed = try XCTUnwrap(Self.bytes(hex: try XCTUnwrap(verdict["framedHex"] as? String)))
        XCTAssertEqual(framed.count, welcome.count + 1024)

        XCTAssertEqual(try bo.join(welcome: framed), group)
        let hello = try ada.encrypt(groupID: group, plaintext: Data("hello".utf8))
        guard case let .application(heard, _, _) = try bo.processMessage(groupID: group, message: hello)
        else {
            return XCTFail("the joiner did not read the group's message")
        }
        XCTAssertEqual(heard, Data("hello".utf8))

        // A refused frame spends its key package, so the stray one goes last.
        var stray = framed
        stray[stray.count - 1] = 1
        XCTAssertThrowsError(try bo.join(welcome: stray))
    }

    private static func bytes(hex: String) -> Data? {
        let digits = Array(hex.utf8)
        guard digits.count % 2 == 0 else { return nil }
        var out = Data(capacity: digits.count / 2)
        var index = 0
        while index < digits.count {
            guard let byte = UInt8(String(decoding: digits[index ..< index + 2], as: UTF8.self), radix: 16)
            else { return nil }
            out.append(byte)
            index += 2
        }
        return out
    }
}
