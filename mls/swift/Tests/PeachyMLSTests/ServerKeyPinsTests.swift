// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// The carried server keys across the C door, read against the one file they
/// come from (`mls/core/pinned-server-keys.json`). The rule itself is
/// `mls/core/tests/server_key_pins.rs`.
final class ServerKeyPinsTests: XCTestCase {
    private static var pinnedURL: URL {
        URL(fileURLWithPath: #filePath)   // …/mls/swift/Tests/PeachyMLSTests/ServerKeyPinsTests.swift
            .deletingLastPathComponent()  // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()  // …/mls/swift/Tests
            .deletingLastPathComponent()  // …/mls/swift
            .deletingLastPathComponent()  // …/mls
            .appendingPathComponent("core/pinned-server-keys.json")
    }

    /// The carried set for `server`, as a server holding exactly it would
    /// publish it.
    private func published(_ server: String, plus extra: [[String: Any]] = []) throws -> String {
        let data = try Data(contentsOf: Self.pinnedURL)
        let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let servers = try XCTUnwrap(root["servers"] as? [String: [[String: String]]])
        let carried = try XCTUnwrap(servers[server])
        XCTAssertFalse(carried.isEmpty, "\(server) carries no keys")
        let keys: [[String: Any]] = extra + carried.map {
            ["kid": $0["kid"] ?? "", "publicKey": $0["publicKey"] ?? "", "current": false, "use": "device"]
        }
        let body = try JSONSerialization.data(withJSONObject: ["enabled": true, "keys": keys])
        return String(decoding: body, as: UTF8.self)
    }

    func testEveryCarriedSetMatchesItsOwnPublishedList() throws {
        for server in ["production", "development"] {
            XCTAssertEqual(
                try MLSClient.serverKeyPinReport(publishedJSON: try published(server), server: server), "")
        }
    }

    func testAKeyTheBuildDoesNotCarryIsReportedAndNarrowedAway() throws {
        let stranger = try TestIssuer(seed: 92)
        let strangerRoot = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(stranger.trustedKeysJSON.utf8)) as? [String: Any])
        let strangerKeys = try XCTUnwrap(strangerRoot["keys"] as? [[String: Any]])
        let strangerKid = try XCTUnwrap(strangerKeys.first?["kid"] as? String)
        let list = try published("production", plus: strangerKeys)

        let report = try MLSClient.serverKeyPinReport(publishedJSON: list, server: "production")
        XCTAssertEqual(report, "published but not pinned: \(strangerKid)")

        let narrowed = try MLSClient.serverKeysPinned(publishedJSON: list, server: "production")
        XCTAssertFalse(narrowed.contains(strangerKid))
        XCTAssertEqual(try MLSClient.serverKeyPinReport(publishedJSON: narrowed, server: "production"), "")
    }

    func testAnUnknownSetNameThrows() {
        XCTAssertThrowsError(
            try MLSClient.serverKeyPinReport(publishedJSON: #"{"keys":[]}"#, server: "staging"))
    }
}
