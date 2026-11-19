// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// `mls/fixtures/calls.json`, resolved from this file's path like every other
/// fixture: one file for four clients.
enum CallsFixture {
    static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)   // …/mls/swift/Tests/PeachyMLSTests/CallsFixtureTests.swift
            .deletingLastPathComponent()  // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()  // …/mls/swift/Tests
            .deletingLastPathComponent()  // …/mls/swift
            .deletingLastPathComponent()  // …/mls
            .appendingPathComponent("fixtures/calls.json")
    }

    static func cases() throws -> [[String: Any]] {
        let url = fixtureURL
        guard let data = try? Data(contentsOf: url),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              root["version"] as? Int == 1,
              let cases = root["cases"] as? [[String: Any]]
        else {
            throw RulesFixture.Failure.fixtureUnreadable(url.path)
        }
        return cases
    }
}

/// The golden calls fixture, replayed from Swift (docs/calls.md §Keys,
/// §Signaling, §Ringing), and a call carried between two real clients.
///
/// `mls/core/tests/calls_fixture.rs`, `mls/wasm/tests/node/calls.test.mjs` and
/// the Android binding's `CallsFixtureTest` (not in this repository) are the other
/// three replays.
final class CallsFixtureTests: XCTestCase {
    private let calls = ["constants", "senderKey", "encode", "decode", "sealLive", "openLive", "liveReplay", "envelope", "ring", "selfUpdateOffset", "senderKeyV2", "mediaAdvance", "mediaKeyPair", "openMediaGrant"]
    private let group = Data("peachy-call-group".utf8)
    private let callId = DeviceLinkFixture.bytes("00112233445566778899aabbccddeeff")

    private func json(_ text: String) throws -> Any {
        try JSONSerialization.jsonObject(with: Data(text.utf8), options: [.fragmentsAllowed])
    }

    private func same(_ a: Any, _ b: Any) -> Bool {
        NSArray(object: a).isEqual(NSArray(object: b))
    }

    func testEveryCaseGetsTheVerdictItExpectsThroughTheFixtureDoor() throws {
        let cases = try CallsFixture.cases()
        XCTAssertGreaterThanOrEqual(cases.count, 100, "the fixture shrank or stopped parsing")
        var failures: [String] = []
        var ids = Set<String>()
        for testCase in cases {
            let id = testCase["id"] as? String ?? "<no id>"
            XCTAssertFalse(ids.contains(id), "two cases share the id \(id)")
            ids.insert(id)
            XCTAssertEqual(testCase["kind"] as? String, "call", id)
            let expectError = testCase["expectError"] as? String
            XCTAssertTrue((testCase["expect"] != nil) != (expectError != nil), "case \(id): exactly one of expect / expectError")
            do {
                let verdict = try json(try RulesFixture.evaluate(case: testCase))
                if let expectError {
                    failures.append("  \(id): expected an error with \(expectError), got \(verdict)")
                } else if !same(verdict, testCase["expect"]!) {
                    failures.append("  \(id)\n    expected \(testCase["expect"]!)\n    actual   \(verdict)")
                }
            } catch {
                if let expectError, "\(error)".contains(expectError) { continue }
                failures.append("  \(id): refused: \(error)")
            }
        }
        XCTAssertTrue(failures.isEmpty, "\(failures.count) cases disagree:\n" + failures.joined(separator: "\n"))
        XCTAssertEqual(Set(cases.compactMap { $0["call"] as? String }), Set(calls))
    }

    /// The key, codec and ring cases through what the Apple apps link, and
    /// every signal through the typed model and back.
    func testTheProductDoorsAgreeWithTheFixture() throws {
        var failures: [String] = []
        var reached = 0
        for testCase in try CallsFixture.cases() {
            let id = testCase["id"] as? String ?? "<no id>"
            let expectError = testCase["expectError"] as? String
            let actual: Any
            do {
                switch testCase["call"] as? String {
                case "senderKey":
                    let root = DeviceLinkFixture.bytes(testCase["callRootHex"] as! String)
                    let leaf = (testCase["leafIndex"] as! NSNumber).uint32Value
                    let sender = try MLSClient.callSenderKey(callRoot: root, leafIndex: leaf)
                    actual = [
                        "senderKeyHex": DeviceLinkFixture.hex(sender),
                        "keyIndex": (testCase["epoch"] as! NSNumber).uint64Value % 256,
                        "frameKeyHex": DeviceLinkFixture.hex(try MLSClient.callFrameKey(senderKey: sender)),
                    ] as [String: Any]
                case "encode":
                    let signal = testCase["signal"] as! [String: Any]
                    let text = String(decoding: try JSONSerialization.data(withJSONObject: signal), as: UTF8.self)
                    actual = ["bytesHex": DeviceLinkFixture.hex(try MLSClient.encodeCallSignal(json: text))]
                    // The typed model reads it and writes it back the same.
                    if expectError == nil {
                        let typed = try CallSignal(jsonObject: signal)
                        if !same(typed.jsonObject(), signal) {
                            failures.append("  \(id): the typed model wrote \(typed.jsonObject())")
                        }
                    }
                case "decode":
                    let text = try MLSClient.decodeCallSignal(DeviceLinkFixture.bytes(testCase["bytesHex"] as! String))
                    actual = ["signal": try json(text)]
                case "ring":
                    let state: String? = testCase["state"] is NSNull ? nil : String(
                        decoding: try JSONSerialization.data(withJSONObject: testCase["state"]!), as: UTF8.self
                    )
                    let event = String(decoding: try JSONSerialization.data(withJSONObject: testCase["event"]!), as: UTF8.self)
                    actual = try json(try MLSClient.callRingStep(state: state, event: event))
                default:
                    continue
                }
            } catch {
                reached += 1
                if let expectError, "\(error)".contains(expectError) { continue }
                failures.append("  \(id): threw \(error)")
                continue
            }
            reached += 1
            if let expectError {
                failures.append("  \(id): expected an error with \(expectError), got \(actual)")
            } else if !same(actual, testCase["expect"]!) {
                failures.append("  \(id)\n    expected \(testCase["expect"]!)\n    actual   \(actual)")
            }
        }
        XCTAssertGreaterThanOrEqual(reached, 100)
        XCTAssertTrue(failures.isEmpty, "\(failures.count) cases disagree:\n" + failures.joined(separator: "\n"))
    }

    private func openCall(_ receiver: MLSClient, _ envelope: Data) throws -> OpenedCallSignal {
        let opened = try XCTUnwrap(try receiver.openEnvelope(envelope), "the envelope opens")
        XCTAssertEqual(opened.kind, EnvelopeKind.call)
        XCTAssertEqual(opened.groupId, group)
        return try receiver.openCallSignal(groupID: group, inner: opened.inner)
    }

    func testTwoMembersDeriveTheSameKeysAndACallRoundTrips() throws {
        let issuer = try TestIssuer(seed: 71)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 5)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 6)
        try ada.createGroup(id: group)
        let add = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(add.welcome))

        let keys = try ada.callKeys(groupID: group, callId: callId)
        XCTAssertEqual(keys, try bo.callKeys(groupID: group, callId: callId))
        XCTAssertEqual(keys.senders.count, 2)
        XCTAssertEqual(UInt64(keys.keyIndex), keys.epoch % 256)
        XCTAssertEqual(
            keys.callRoot,
            try ada.exportSecret(groupID: group, label: CallConstants.exporterLabel, context: callId, length: 32)
        )
        for sender in keys.senders {
            XCTAssertEqual(sender.key, try MLSClient.callSenderKey(callRoot: keys.callRoot, leafIndex: sender.leafIndex))
        }

        let offer = CallSignal(callId: callId, body: .offer(media: .video, ring: true, createdAtMs: 1_789_516_800_000))
        XCTAssertTrue(offer.isUrgent)
        let opened = try openCall(bo, try ada.sealCallSignal(groupID: group, offer))
        XCTAssertEqual(opened.lane, .mls)
        XCTAssertTrue(opened.urgent)
        XCTAssertEqual(opened.sender?.actorId, "actor-ada")
        XCTAssertEqual(opened.signal, offer)

        let hangup = CallSignal(callId: callId, body: .hangup(reason: .declinedElsewhere))
        XCTAssertEqual(try openCall(ada, try bo.sealCallSignal(groupID: group, hangup)).signal, hangup)

        // An in-call control names its sender: it rides the MLS lane, never the live one.
        let media = CallSignal(callId: callId, body: .media(audioOn: true, videoOn: false, presenting: true))
        let control = try openCall(ada, try bo.sealCallSignal(groupID: group, media))
        XCTAssertEqual(control.lane, .mls)
        XCTAssertEqual(control.sender?.actorId, "actor-bo")
        XCTAssertFalse(control.urgent)
        XCTAssertEqual(control.signal, media)

        // A device's own Left goes signed, whatever its core remembers of the
        // call, so every participant that bound it rotates past it.
        let left = CallSignal(callId: callId, body: .left(participantId: "p-bo"))
        let signedLeft = try openCall(ada, try bo.sealCallSignal(groupID: group, left))
        XCTAssertEqual(signedLeft.lane, .mls)
        XCTAssertEqual(signedLeft.sender?.actorId, "actor-bo")
        XCTAssertNil(signedLeft.unboundLeaf, "Ada never bound Bo's leaf, so it unbinds nothing")
        XCTAssertFalse(signedLeft.urgent)
        XCTAssertEqual(signedLeft.signal, left)

        // A direct 1:1 call's SDP rides the MLS lane, signed, never urgent.
        let direct = CallSignal(callId: callId, body: .direct(toLeaf: 0, sdp: "v=0\r\n", offer: true))
        XCTAssertFalse(direct.isUrgent)
        let openedDirect = try openCall(ada, try bo.sealCallSignal(groupID: group, direct))
        XCTAssertEqual(openedDirect.lane, .mls)
        XCTAssertFalse(openedDirect.urgent)
        XCTAssertEqual(openedDirect.sender?.actorId, "actor-bo")
        XCTAssertNotNil(openedDirect.senderLeaf)
        XCTAssertEqual(openedDirect.signal, direct)

        // A participant's first Joined goes signed and names its own leaf (D10).
        let adaLeaf = try XCTUnwrap(opened.senderLeaf)
        let joined = { (leaf: UInt32) in
            CallSignal(callId: self.callId, body: .joined(participantId: "p", sessionId: "", trackNames: [], leafIndex: leaf))
        }
        // A keyless Joined from a device that is not a participant is refused:
        // only `start` gives it the call keys a Joined carries.
        XCTAssertThrowsError(try ada.sealCallSignalSigned(groupID: group, joined(adaLeaf))) { error in
            XCTAssertTrue("\(error)".contains("call state lost"), "\(error)")
        }
        let start = "{\"op\":\"start\",\"callId\":\"\(DeviceLinkFixture.hex(callId))\","
            + "\"participantId\":\"p\",\"sessionId\":\"s\",\"trackNames\":[]}"
        _ = try ada.callMedia(groupID: group, request: start)
        let signed = try openCall(bo, try ada.sealCallSignalSigned(groupID: group, joined(adaLeaf)))
        XCTAssertEqual(signed.lane, .mls)
        XCTAssertEqual(signed.senderLeaf, adaLeaf)
        // The typed view reads the keys and the mark the core filled in, and
        // writes them back.
        guard case let .joined(_, _, _, _, mediaKey, _, mediaKeyPq, participation) = signed.signal.body else {
            return XCTFail("not a Joined: \(signed.signal.body)")
        }
        XCTAssertEqual(mediaKey.count, 32)
        XCTAssertEqual(mediaKeyPq.count, 1216)
        XCTAssertEqual(participation.count, 24)
        XCTAssertEqual(try CallSignal(jsonObject: signed.signal.jsonObject()), signed.signal)
        let forged = try XCTUnwrap(try bo.openEnvelope(try ada.sealCallSignalSigned(groupID: group, joined(adaLeaf + 1))))
        XCTAssertThrowsError(try bo.openCallSignal(groupID: group, inner: forged.inner))
        XCTAssertEqual(try MLSClient.callSelfUpdateOffsetMs(rank: 1, participants: 4), 150_000)

        // A new epoch is a new ring, and the committer can load it first.
        let update = try ada.selfUpdate(groupID: group)
        let pending = try ada.pendingCallKeys(groupID: group, callId: callId)
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.processCommit(groupID: group, message: update.commit)
        let next = try bo.callKeys(groupID: group, callId: callId)
        XCTAssertEqual(next.epoch, keys.epoch + 1)
        XCTAssertEqual(next.callRoot, pending.callRoot)
        XCTAssertNotEqual(next.callRoot, keys.callRoot)
        XCTAssertEqual(next.keyIndex, keys.keyIndex &+ 1)
    }
}
