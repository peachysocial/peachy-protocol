// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// `mls/fixtures/account-store.json`, read for the replay below.
///
/// Resolved from THIS FILE's path, like `DeviceLinkFixture.fixtureURL` and for
/// the same reason: the fixture belongs to four clients, and a copy under
/// `Tests/` would be a second fixture pretending to be the first.
enum AccountStoreFixture {
    static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)   // …/mls/swift/Tests/PeachyMLSTests/AccountStoreFixtureTests.swift
            .deletingLastPathComponent()  // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()  // …/mls/swift/Tests
            .deletingLastPathComponent()  // …/mls/swift
            .deletingLastPathComponent()  // …/mls
            .appendingPathComponent("fixtures/account-store.json")
    }

    static func load() throws -> [String: Any] {
        let url = fixtureURL
        guard let data = try? Data(contentsOf: url),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw RulesFixture.Failure.fixtureUnreadable(url.path)
        }
        return root
    }
}

/// The golden account-store fixture, replayed from Swift.
///
/// `mls/core/tests/account_store_fixture.rs` generates the table and replays
/// it in Rust; `mls/wasm/tests/node/account-store.test.mjs` and
/// the Android binding's `AccountStoreFixtureTest` (not in this repository) are
/// the other two bindings. Two passes here, as there:
///
///  1. every case through the shared fixture door (`kind: "account_store"`);
///  2. every open case through ``MLSClient/storeOpen(accountKey:id:value:)`` and
///     ``MLSClient/accountKeyOpen(recipientSeed:approverSigningKey:deviceId:box:)``,
///     which are what the Apple apps link and which the fixture door does not
///     reach.
///
/// What only this replay can catch is the crossing: an empty plaintext that
/// arrived as a thrown error or a crash because a null buffer was read as a
/// failure, a refusal that arrived as empty `Data`, a box that lost a byte.
final class AccountStoreFixtureTests: XCTestCase {
    private let formatVersion = 1
    private let calls = [
        "recordKey", "storeOpen", "boxOpen", "boxAccept", "boxAcceptHybrid", "noteSender", "noteOpenSigned",
        "transferKeyOpen",
    ]

    private func cases() throws -> [[String: Any]] {
        let root = try AccountStoreFixture.load()
        return try XCTUnwrap(root["cases"] as? [[String: Any]], "`cases` is an array of objects")
    }

    private func bytes(_ testCase: [String: Any], _ key: String) throws -> Data {
        DeviceLinkFixture.bytes(try XCTUnwrap(testCase[key] as? String, "missing \(key)"))
    }

    func testTheFixtureIsTheFormatThisBuildReads() throws {
        let root = try AccountStoreFixture.load()
        XCTAssertEqual(root["version"] as? Int, formatVersion)
        XCTAssertGreaterThanOrEqual(try cases().count, 30, "the fixture shrank or stopped parsing")
        for testCase in try cases() {
            let id = testCase["id"] ?? "<no id>"
            XCTAssertEqual(testCase["kind"] as? String, "account_store", "case \(id)")
            XCTAssertNotEqual(
                testCase["expect"] == nil, testCase["expectError"] == nil,
                "case \(id) needs exactly one of `expect` and `expectError`"
            )
            XCTAssertTrue(calls.contains(testCase["call"] as? String ?? ""), "case \(id)")
        }
        let reached = Set(try cases().compactMap { $0["call"] as? String })
        XCTAssertEqual(reached, Set(calls), "every call is reached by some case")
    }

    func testEveryCaseGetsTheVerdictItExpectsThroughTheFixtureDoor() throws {
        var failures: [String] = []
        var ids = Set<String>()
        for testCase in try cases() {
            let id = testCase["id"] as? String ?? "<no id>"
            XCTAssertFalse(ids.contains(id), "two cases share the id \(id)")
            ids.insert(id)

            if let expectedError = testCase["expectError"] as? String {
                do {
                    let answered = try RulesFixture.evaluate(case: testCase)
                    failures.append("  \(id)\n    expected a refusal naming \(expectedError)\n    actual   \(answered)")
                } catch {
                    let message = String(describing: error)
                    if !message.contains(expectedError) {
                        failures.append("  \(id)\n    expected a refusal naming \(expectedError)\n    actual   \(message)")
                    }
                }
                continue
            }
            let expected = try XCTUnwrap(testCase["expect"] as? [String: Any], "case \(id) has no `expect`")
            do {
                let verdictText = try RulesFixture.evaluate(case: testCase)
                let verdict = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: Data(verdictText.utf8)) as? [String: Any]
                )
                if NSDictionary(dictionary: verdict) != NSDictionary(dictionary: expected) {
                    failures.append("  \(id)\n    expected \(expected)\n    actual   \(verdict)")
                }
            } catch {
                failures.append("  \(id)\n    expected \(expected)\n    actual   refused: \(error)")
            }
        }
        XCTAssertTrue(failures.isEmpty, "\(failures.count) cases disagree:\n" + failures.joined(separator: "\n"))
    }

    func testEveryOpenCaseAgreesThroughTheProductSurface() throws {
        var failures: [String] = []
        var reached = 0
        for testCase in try cases() {
            let id = testCase["id"] as? String ?? "<no id>"
            let expectedError = testCase["expectError"] as? String
            let expected = testCase["expect"] as? [String: Any]
            let outcome: Result<Data, Error>
            let key: String
            switch testCase["call"] as? String {
            case "storeOpen":
                key = "plaintextHex"
                outcome = Result {
                    try MLSClient.storeOpen(
                        accountKey: try bytes(testCase, "accountKeyHex"),
                        id: try bytes(testCase, "idHex"),
                        value: try bytes(testCase, "valueHex")
                    )
                }
            case "noteSender":
                // The sender crosses as a string; compared as its UTF-8 bytes.
                key = "senderDeviceId"
                outcome = Result {
                    Data(
                        try MLSClient.noteSender(
                            accountKey: try bytes(testCase, "accountKeyHex"),
                            id: try bytes(testCase, "idHex"),
                            value: try bytes(testCase, "valueHex")
                        ).utf8
                    )
                }
            case "noteOpenSigned":
                key = "plaintextHex"
                outcome = Result {
                    try MLSClient.noteOpenSigned(
                        accountKey: try bytes(testCase, "accountKeyHex"),
                        id: try bytes(testCase, "idHex"),
                        value: try bytes(testCase, "valueHex"),
                        senderDeviceId: testCase["deviceId"] as? String ?? "",
                        senderSigningKey: try bytes(testCase, "senderKeyHex"),
                        nowMs: (testCase["nowMs"] as? NSNumber)?.int64Value ?? 0
                    )
                }
            case "transferKeyOpen":
                key = "transferKeyHex"
                outcome = Result {
                    try MLSClient.transferKeyOpen(
                        recipientSeed: try bytes(testCase, "recipientSeedHex"),
                        deviceId: testCase["deviceId"] as? String ?? "",
                        box: try bytes(testCase, "boxHex")
                    )
                }
            case "boxOpen":
                key = "accountKeyHex"
                outcome = Result {
                    try MLSClient.accountKeyOpen(
                        recipientSeed: try bytes(testCase, "recipientSeedHex"),
                        approverSigningKey: try bytes(testCase, "approverKeyHex"),
                        deviceId: testCase["deviceId"] as? String ?? "",
                        box: try bytes(testCase, "boxHex")
                    )
                }
            case "boxAcceptHybrid":
                key = "accountKeyHex"
                outcome = Result {
                    try MLSClient.accountKeyAcceptHybrid(
                        recipientSeed: try bytes(testCase, "recipientSeedHex"),
                        approverSigningKey: try bytes(testCase, "approverKeyHex"),
                        deviceId: testCase["deviceId"] as? String ?? "",
                        box: try bytes(testCase, "boxHex"),
                        linkKeySeed: DeviceLinkFixture.bytes(testCase["linkKeySeedHex"] as? String ?? ""),
                        confirmedApproverKey: DeviceLinkFixture.bytes(
                            testCase["confirmedApproverKeyHex"] as? String ?? ""
                        ),
                        serverApprovalAllowed: testCase["serverApprovalAllowed"] as? Bool ?? false
                    )
                }
            default:
                continue
            }
            reached += 1
            switch (outcome, expectedError) {
            case let (.success(data), nil):
                let want = key == "senderDeviceId"
                    ? DeviceLinkFixture.hex(Data((expected?[key] as? String ?? "").utf8))
                    : expected?[key] as? String
                if DeviceLinkFixture.hex(data) != want {
                    failures.append("  \(id): expected \(expected?[key] ?? "?"), got \(DeviceLinkFixture.hex(data))")
                }
            case let (.success(data), .some(message)):
                failures.append("  \(id): expected a refusal naming \(message), got \(DeviceLinkFixture.hex(data))")
            case let (.failure(error), nil):
                failures.append("  \(id): refused: \(error)")
            case let (.failure(error), .some(message)):
                guard let mlsError = error as? MLSError else {
                    failures.append("  \(id): a refusal is an MLSError, not \(error)")
                    continue
                }
                XCTAssertEqual(mlsError.code, .invalidArgument, id)
                if !mlsError.message.contains(message) {
                    failures.append("  \(id): expected a refusal naming \(message), got \(mlsError.message)")
                }
            }
        }
        XCTAssertGreaterThanOrEqual(reached, 20, "the open cases stopped reaching the product surface")
        XCTAssertTrue(failures.isEmpty, "\(failures.count) cases disagree:\n" + failures.joined(separator: "\n"))
    }

    func testTheRandomDoorsRoundTripIncludingAnEmptyPlaintext() throws {
        let key = try MLSClient.generateAccountKey()
        XCTAssertEqual(key.count, 32)
        XCTAssertNotEqual(key, try MLSClient.generateAccountKey())

        let id = Data(repeating: 0x11, count: 16)
        for plaintext in [Data(), Data(#"{"kind":"account"}"#.utf8)] {
            let value = try MLSClient.storeSeal(accountKey: key, id: id, plaintext: plaintext)
            XCTAssertEqual((value.count - 29) % 256, 0)
            XCTAssertEqual(try MLSClient.storeOpen(accountKey: key, id: id, value: value), plaintext)
        }
        let phoneSeed = Data(repeating: 0x11, count: 32)
        let signed = try MLSClient.noteSealSigned(
            accountKey: key, id: id, plaintext: Data("{}".utf8),
            senderDeviceId: "device-ada-phone", issuedAtMs: 1_790_000_000_000, deviceSeed: phoneSeed
        )
        XCTAssertEqual(try MLSClient.noteSender(accountKey: key, id: id, value: signed), "device-ada-phone")
        XCTAssertThrowsError(try MLSClient.storeOpen(accountKey: key, id: id, value: signed))
        XCTAssertEqual(
            try MLSClient.noteOpenSigned(
                accountKey: key, id: id, value: signed, senderDeviceId: "device-ada-phone",
                senderSigningKey: try MLSClient.signingKeyPublicKey(seed: phoneSeed), nowMs: 1_790_000_000_000
            ),
            Data("{}".utf8)
        )
        XCTAssertThrowsError(
            try MLSClient.storeSeal(accountKey: key, id: id.prefix(15), plaintext: Data([1]))
        ) { error in
            XCTAssertTrue(String(describing: error).contains("exactly 16 bytes, got 15"), "\(error)")
        }

        let approverSeed = Data(repeating: 0x11, count: 32)
        let recipientSeed = Data(repeating: 0x33, count: 32)
        let deviceId = "0f8e2b1c-6a4d-4e3f-9b2a-7c5d1e0f3a9b"
        let box = try MLSClient.accountKeySeal(
            approverSeed: approverSeed,
            recipientSigningKey: try MLSClient.signingKeyPublicKey(seed: recipientSeed),
            deviceId: deviceId,
            accountKey: key
        )
        XCTAssertEqual(box.count, 93)
        XCTAssertEqual(
            try MLSClient.accountKeyOpen(
                recipientSeed: recipientSeed,
                approverSigningKey: try MLSClient.signingKeyPublicKey(seed: approverSeed),
                deviceId: deviceId,
                box: box
            ),
            key
        )
        XCTAssertThrowsError(
            try MLSClient.accountKeyOpen(
                recipientSeed: recipientSeed,
                approverSigningKey: try MLSClient.signingKeyPublicKey(seed: Data(repeating: 0x44, count: 32)),
                deviceId: deviceId,
                box: box
            )
        ) { error in
            XCTAssertTrue(String(describing: error).contains("does not open"), "\(error)")
        }

        // The new device's door never opens a version-2 box (the removed QR
        // code's, which no door seals any more), and opens a version-1 box
        // only under its own switch for server approvals.
        let approverKey = try MLSClient.signingKeyPublicKey(seed: approverSeed)
        var linked = box
        linked[linked.startIndex] = 0x02
        XCTAssertThrowsError(
            try MLSClient.accountKeyAcceptHybrid(
                recipientSeed: recipientSeed, approverSigningKey: approverKey, deviceId: deviceId,
                box: linked, linkKeySeed: Data(), confirmedApproverKey: approverKey, serverApprovalAllowed: true
            )
        ) { error in
            XCTAssertTrue(String(describing: error).contains("showed no QR code"), "\(error)")
        }
        XCTAssertThrowsError(
            try MLSClient.accountKeyAcceptHybrid(
                recipientSeed: recipientSeed, approverSigningKey: approverKey, deviceId: deviceId,
                box: box, linkKeySeed: Data(), confirmedApproverKey: approverKey, serverApprovalAllowed: false
            )
        ) { error in
            XCTAssertTrue(String(describing: error).contains("post-quantum box"), "\(error)")
        }
        XCTAssertEqual(
            try MLSClient.accountKeyAcceptHybrid(
                recipientSeed: recipientSeed, approverSigningKey: approverKey, deviceId: deviceId,
                box: box, linkKeySeed: Data(), confirmedApproverKey: Data(), serverApprovalAllowed: true
            ),
            key
        )

        // A hand-off's key, sealed to the device it goes to: no other seed
        // opens it.
        let transfer = try MLSClient.transferKeySeal(
            recipientSigningKey: try MLSClient.signingKeyPublicKey(seed: recipientSeed),
            deviceId: deviceId, key: key)
        XCTAssertEqual(transfer.count, 93)
        XCTAssertEqual(
            try MLSClient.transferKeyOpen(recipientSeed: recipientSeed, deviceId: deviceId, box: transfer),
            key)
        XCTAssertThrowsError(
            try MLSClient.transferKeyOpen(recipientSeed: approverSeed, deviceId: deviceId, box: transfer)
        ) { error in
            XCTAssertTrue(String(describing: error).contains("does not open"), "\(error)")
        }
    }
}
