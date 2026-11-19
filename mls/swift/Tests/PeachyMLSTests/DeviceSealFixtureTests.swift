// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// The golden device-seal fixture, replayed through the C door from Swift.
///
/// `mls/fixtures/device-seal.json` pins the device seal
/// (`mls/core/src/device_seal.rs`): its bytes for given inputs, what opens and
/// what is refused, and that no build SENDS it (`DEVICE_SEAL_SENDS` is false).
/// The other replays are `mls/core/tests/device_seal_fixture.rs`,
/// `mls/wasm/tests/node/device-seal.test.mjs` and
/// the Android binding's `DeviceSealFixtureTest` (not in this repository). It goes
/// through the same fixture door as the other tables (`RulesFixture.evaluate`),
/// told apart by each case's `kind`, and also drives the product door an app
/// calls: ``MLSClient/holdEnvelope(mailboxKind:id:receivedAtMs:envelope:deviceSeal:)``
/// with a seal beside an envelope that opens for no group here.
final class DeviceSealFixtureTests: XCTestCase {
    private let formatVersion = 1
    private let calls = ["constants", "seal", "open"]

    private static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()  // …/mls/swift/Tests
            .deletingLastPathComponent()  // …/mls/swift
            .deletingLastPathComponent()  // …/mls
            .appendingPathComponent("fixtures/device-seal.json")
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
            XCTAssertEqual(testCase["kind"] as? String, "device_seal", "case \(id) has no kind")
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
            "\(failures.count) of \(all.count) device-seal cases disagree:\n"
                + failures.joined(separator: "\n")
        )
    }

    func testTheClientDoorKeepsASealedEnvelopeAndOpensItOnceTheCopyIsPastItsEpoch() throws {
        let issuer = try TestIssuer(seed: 7)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 0x11)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 0x22)
        let group = Data("device-seal-room".utf8)
        try ada.createGroup(id: group)
        let bundle = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        _ = try ada.mergePendingCommit(groupID: group)
        XCTAssertEqual(try bo.join(welcome: try XCTUnwrap(bundle.welcome)), group)

        // Ada's message, in an envelope keyed by a secret Bo's copy never
        // held, with Ada's seal for Bo carrying it.
        let message = try ada.encrypt(groupID: group, plaintext: Data("missed".utf8))
        let secret = Data(repeating: 0x5a, count: 32)
        let envelope = try Self.door([
            "kind": "roster",
            "call": "seal",
            "epochSecretHex": Self.hex(secret),
            "envelopeKind": 1,
            "innerHex": Self.hex(message),
            "nonceHex": "000102030405060708090a0b",
        ], "envelopeHex")
        let seal = try Self.door([
            "kind": "device_seal",
            "call": "seal",
            "senderSeedHex": Self.hex(TestIssuer.deviceSeed(0x11)),
            "recipientKeyHex": Self.hex(
                try MLSClient.signingKeyPublicKey(seed: TestIssuer.deviceSeed(0x22))),
            "groupIdHex": Self.hex(group),
            "epochSecretHex": Self.hex(secret),
            "envelopeHex": Self.hex(envelope),
            "ephemeralHex": Self.hex(Data(repeating: 0x42, count: 32)),
        ], "sealHex")
        XCTAssertEqual(seal.count, 226)
        XCTAssertNil(try bo.openEnvelope(envelope), "opens for nothing Bo holds")
        XCTAssertEqual(
            try bo.holdEnvelope(
                mailboxKind: 1, id: "env-sealed", receivedAtMs: Self.nowMs, envelope: envelope,
                deviceSeal: seal),
            .kept)
        XCTAssertNil(try bo.nextReopenable(), "Bo's copy is at the message's epoch: it waits")

        let update = try ada.selfUpdate(groupID: group)
        _ = try ada.mergePendingCommit(groupID: group)
        _ = try bo.processCommit(groupID: group, message: update.commit)
        let held = try XCTUnwrap(try bo.nextReopenable(), "handed out once Bo is past the epoch")
        XCTAssertEqual(held.id, "env-sealed")
        let opened = try XCTUnwrap(try bo.openEnvelope(held.envelope), "opens on the seal's secret")
        XCTAssertEqual(opened.groupId, group)
        XCTAssertEqual(opened.kind, 1)
        XCTAssertEqual(opened.inner, message)
        XCTAssertNil(try bo.nextReopenable(), "handed out once a pass")
        // From a leaf of Bo's copy: taken through as any envelope, naming nobody.
        XCTAssertNil(try bo.heldDisposition(id: "env-sealed"))
        // Kept, and still granted, until released; released, the grant is spent.
        XCTAssertNotNil(try bo.openEnvelope(held.envelope), "still granted before the release")
        XCTAssertTrue(try bo.releaseHeld(id: "env-sealed"))
        XCTAssertNil(try bo.openEnvelope(held.envelope), "the release spends the grant")
        XCTAssertNil(try bo.nextReopenable())

        // No seal, or one that does not open: held as before, and never granted.
        let other = try Self.door([
            "kind": "roster",
            "call": "seal",
            "epochSecretHex": Self.hex(Data(repeating: 0x6b, count: 32)),
            "envelopeKind": 1,
            "innerHex": Self.hex(try ada.encrypt(groupID: group, plaintext: Data("unsealed".utf8))),
            "nonceHex": "0c0d0e0f1011121314151617",
        ], "envelopeHex")
        XCTAssertEqual(
            try bo.holdEnvelope(
                mailboxKind: 1, id: "env-plain", receivedAtMs: Self.nowMs, envelope: other),
            .kept)
        // The same bytes again, under a new id and a seal that does not open:
        // held once.
        XCTAssertEqual(
            try bo.holdEnvelope(
                mailboxKind: 1, id: "env-garbled", receivedAtMs: Self.nowMs, envelope: other,
                deviceSeal: Data(repeating: 1, count: 226)),
            .notKept)
        XCTAssertNil(try bo.nextReopenable())
    }

    private static var nowMs: UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }

    private static func door(_ testCase: [String: Any], _ key: String) throws -> Data {
        let answer = try RulesFixture.evaluate(case: testCase)
        let verdict = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(answer.utf8)) as? [String: Any]
        )
        return try XCTUnwrap(bytes(hex: try XCTUnwrap(verdict[key] as? String)))
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func bytes(hex: String) -> Data? {
        let digits = Array(hex.utf8)
        guard digits.count % 2 == 0 else { return nil }
        var out = Data(capacity: digits.count / 2)
        var index = 0
        while index < digits.count {
            guard let byte = UInt8(String(decoding: digits[index..<index + 2], as: UTF8.self), radix: 16)
            else { return nil }
            out.append(byte)
            index += 2
        }
        return out
    }
}
