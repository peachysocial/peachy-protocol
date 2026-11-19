// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// `mls/fixtures/rosters.json`, read for the replay below.
///
/// Resolved from THIS FILE's path, like `AccountStoreFixture.fixtureURL` and
/// for the same reason: the fixture belongs to four clients, and a copy under
/// `Tests/` would be a second fixture pretending to be the first.
enum RostersFixture {
    static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)   // …/mls/swift/Tests/PeachyMLSTests/RostersFixtureTests.swift
            .deletingLastPathComponent()  // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()  // …/mls/swift/Tests
            .deletingLastPathComponent()  // …/mls/swift
            .deletingLastPathComponent()  // …/mls
            .appendingPathComponent("fixtures/rosters.json")
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

/// The golden rosters fixture, replayed from Swift.
///
/// `mls/core/tests/rosters_fixture.rs` replays it in Rust;
/// `mls/wasm/tests/node/rosters.test.mjs` and
/// the Android binding's `RostersFixtureTest` (not in this repository) are the
/// other two bindings. Two passes here, as there:
///
///  1. every case through the shared fixture door (`kind: "roster"`);
///  2. the handle, seal and open cases through ``MLSClient/groupHandle(groupId:)``,
///     ``MLSClient/sealEnvelope(groupId:kind:inner:)`` and
///     ``MLSClient/openEnvelope(_:)``, which are what the Apple apps link and
///     which the fixture door does not reach. The product seal draws a random
///     nonce, so a seal case is checked there by opening what it sealed; the
///     fixture door's deterministic bytes are pass 1's job. A case keyed by an
///     epoch secret (`epochSecretHex`, `epochSecretsHex`: version 3) names a
///     secret only a group's epoch derives, which no product door takes: the
///     product seal skips it, and the product open, holding the case's group
///     ids alone, must open nothing.
///
/// What only this replay can catch is the crossing: a "none" that arrived as a
/// thrown error or as an `OpenedEnvelope` with an empty group, a kind that
/// lost its byte, an empty inner that came back as a failure.
final class RostersFixtureTests: XCTestCase {
    private let formatVersion = 1
    private let calls = ["handle", "seal", "open", "judge"]

    private func cases() throws -> [[String: Any]] {
        let root = try RostersFixture.load()
        return try XCTUnwrap(root["cases"] as? [[String: Any]], "`cases` is an array of objects")
    }

    private func bytes(_ testCase: [String: Any], _ key: String) throws -> Data {
        DeviceLinkFixture.bytes(try XCTUnwrap(testCase[key] as? String, "missing \(key)"))
    }

    private func groupId(_ text: Any?) throws -> Data {
        Data(try XCTUnwrap(text as? String, "a group id is a string").utf8)
    }

    /// A client holding exactly `groupIds`, each as a group of one.
    private func client(holding groupIds: [Data], tag: UInt8) throws -> MLSClient {
        let issuer = try TestIssuer(seed: 97)
        let client = try issuer.client(
            actorId: "actor-rosters", deviceId: "device-rosters-\(tag)", tag: tag
        )
        for id in groupIds {
            try client.createGroup(id: id)
        }
        return client
    }

    func testTheFixtureIsTheFormatThisBuildReads() throws {
        let root = try RostersFixture.load()
        XCTAssertEqual(root["version"] as? Int, formatVersion)
        XCTAssertGreaterThanOrEqual(try cases().count, 30, "the fixture shrank or stopped parsing")
        for testCase in try cases() {
            let id = testCase["id"] ?? "<no id>"
            XCTAssertEqual(testCase["kind"] as? String, "roster", "case \(id)")
            XCTAssertNotNil(testCase["expect"] as? [String: Any], "case \(id) has no `expect`")
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

    func testEveryHandleSealAndOpenCaseAgreesThroughTheProductSurface() throws {
        var failures: [String] = []
        var reached = 0
        var tag: UInt8 = 60
        for testCase in try cases() {
            let id = testCase["id"] as? String ?? "<no id>"
            let expected = try XCTUnwrap(testCase["expect"] as? [String: Any], "case \(id)")
            do {
                switch testCase["call"] as? String {
                case "handle":
                    let handle = try MLSClient.groupHandle(groupId: try groupId(testCase["groupId"]))
                    XCTAssertEqual(handle.count, 32, id)
                    if DeviceLinkFixture.hex(handle) != expected["handleHex"] as? String {
                        failures.append("  \(id): expected \(expected["handleHex"] ?? "?"), got \(DeviceLinkFixture.hex(handle))")
                    }
                case "seal" where testCase["epochSecretHex"] != nil:
                    continue
                case "open" where testCase["epochSecretsHex"] != nil:
                    let groups = try XCTUnwrap(testCase["groupIds"] as? [Any], "case \(id)").map { try groupId($0) }
                    tag &+= 1
                    if let opened = try client(holding: groups, tag: tag)
                        .openEnvelope(try bytes(testCase, "envelopeHex")) {
                        failures.append("  \(id): opened by the group id alone, as \(opened)")
                    }
                case "seal":
                    let group = try groupId(testCase["groupId"])
                    let kind = UInt8(try XCTUnwrap(testCase["envelopeKind"] as? Int, "case \(id)"))
                    let inner = try bytes(testCase, "innerHex")
                    // The clientless door seals a seat ask and a link preview
                    // only; every other kind is the client's.
                    if kind != EnvelopeKind.seatAsk && kind != EnvelopeKind.linkPreview {
                        do {
                            _ = try MLSClient.sealEnvelope(groupId: group, kind: kind, inner: inner)
                            failures.append("  \(id): kind \(kind) sealed at the clientless door")
                        } catch let error as MLSError where error.code == .invalidArgument {
                        } catch {
                            failures.append("  \(id): kind \(kind) refused as \(error)")
                        }
                        continue
                    }
                    let sealed = try MLSClient.sealEnvelope(groupId: group, kind: kind, inner: inner)
                    let golden = try XCTUnwrap(expected["envelopeHex"] as? String, "case \(id)")
                    // A case naming no `envelopeVersion` pins what this build
                    // SENDS (version 2): same version byte,
                    // same nonce width, so the same length; the bytes differ by
                    // the nonce. A case naming one pins bytes only the fixture
                    // door seals, so here only its round trip is checked.
                    if testCase["envelopeVersion"] == nil {
                        XCTAssertEqual(sealed.count, golden.count / 2, id)
                        XCTAssertEqual(DeviceLinkFixture.hex(sealed.prefix(1)), String(golden.prefix(2)), id)
                    }
                    tag &+= 1
                    let opened = try client(holding: [group], tag: tag).openEnvelope(sealed)
                    if opened != OpenedEnvelope(groupId: group, kind: kind, inner: inner) {
                        failures.append("  \(id): sealed, then opened as \(String(describing: opened))")
                    }
                case "open":
                    let groups = try XCTUnwrap(testCase["groupIds"] as? [Any], "case \(id)").map { try groupId($0) }
                    tag &+= 1
                    let opened = try client(holding: groups, tag: tag)
                        .openEnvelope(try bytes(testCase, "envelopeHex"))
                    if expected["opened"] as? Bool == true {
                        let want = OpenedEnvelope(
                            groupId: try groupId(expected["groupId"]),
                            kind: UInt8(try XCTUnwrap(expected["envelopeKind"] as? Int)),
                            inner: DeviceLinkFixture.bytes(try XCTUnwrap(expected["innerHex"] as? String))
                        )
                        if opened != want {
                            failures.append("  \(id): expected \(want), got \(String(describing: opened))")
                        }
                    } else if let opened {
                        failures.append("  \(id): expected none, got \(opened)")
                    }
                    // THE CLIENTLESS DOOR (docs/sealed-messages.md §The preview): a
                    // link holder opens it knowing only the group id.
                    if groups.count == 1 {
                        let bare = try MLSClient.openEnvelope(
                            for: groups[0], try bytes(testCase, "envelopeHex"))
                        if bare != opened {
                            failures.append("  \(id): openEnvelope(for:) gave \(String(describing: bare)), the client \(String(describing: opened))")
                        }
                    }
                default:
                    continue
                }
                reached += 1
            } catch {
                failures.append("  \(id): refused: \(error)")
            }
        }
        XCTAssertGreaterThanOrEqual(reached, 11, "the handle, seal and open cases stopped reaching the product surface")
        XCTAssertTrue(failures.isEmpty, "\(failures.count) cases disagree:\n" + failures.joined(separator: "\n"))
    }

    func testAClientsOwnSealIsKeyedByTheEpoch() throws {
        let group = Data("33333333-3333-4333-8333-333333333333".utf8)
        let own = try client(holding: [group], tag: 91)
        let sealed = try own.sealEnvelope(
            groupId: group, kind: EnvelopeKind.message, inner: Data("hello".utf8))
        XCTAssertEqual(sealed.first, 3, "sealed by the epoch")
        XCTAssertEqual(
            try own.openEnvelope(sealed),
            OpenedEnvelope(groupId: group, kind: EnvelopeKind.message, inner: Data("hello".utf8))
        )
        // Not by the group id: another device holding only the id opens nothing.
        XCTAssertNil(try client(holding: [group], tag: 92).openEnvelope(sealed))
        // A seat ask stays keyed by the group id, for an asker that holds no epoch.
        let ask = try own.sealEnvelope(groupId: group, kind: EnvelopeKind.seatAsk, inner: Data("{}".utf8))
        XCTAssertEqual(ask.first, 2)
        XCTAssertEqual(try client(holding: [group], tag: 93).openEnvelope(ask)?.kind, EnvelopeKind.seatAsk)
    }

    func testTheProductDoorsRefuseWhatTheCoreRefuses() throws {
        XCTAssertThrowsError(try MLSClient.groupHandle(groupId: Data())) { error in
            XCTAssertEqual((error as? MLSError)?.code, .invalidArgument)
        }
        XCTAssertThrowsError(
            try MLSClient.sealEnvelope(groupId: Data("g".utf8), kind: 0, inner: Data())
        ) { error in
            XCTAssertEqual((error as? MLSError)?.code, .invalidArgument)
        }
        XCTAssertThrowsError(
            try MLSClient.sealEnvelope(groupId: Data("g".utf8), kind: 7, inner: Data())
        ) { error in
            XCTAssertEqual((error as? MLSError)?.code, .invalidArgument)
        }
        // Two seals of the same bytes differ: the nonce is fresh each time.
        let group = Data("11111111-1111-4111-8111-111111111111".utf8)
        XCTAssertNotEqual(
            try MLSClient.sealEnvelope(groupId: group, kind: EnvelopeKind.seatAsk, inner: Data()),
            try MLSClient.sealEnvelope(groupId: group, kind: EnvelopeKind.seatAsk, inner: Data())
        )
        // A client holding no group opens nothing, and says so without throwing.
        XCTAssertNil(try client(holding: [], tag: 90).openEnvelope(Data([0x02, 0x03])))
    }
}
