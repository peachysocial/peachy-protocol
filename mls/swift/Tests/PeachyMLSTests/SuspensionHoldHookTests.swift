// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// Every call that reaches the store runs inside the installed suspension hold
/// (`MLSClient.swift` §Suspension). A shipped iOS build was killed with
/// `0xdead10cc` while `init` was reading the app-group store and nothing asked
/// iOS to wait; these pin that the open, the calls through `locked`, `close`
/// and `deinit` all pass through the hold, and that a call's error still comes
/// out of it.
final class SuspensionHoldHookTests: XCTestCase {

    /// Counts what passed through the hold, and how deep it was nested.
    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var entries = 0
        private var depth = 0
        private var deepest = 0

        func run(_ body: () -> Void) {
            lock.lock()
            entries += 1
            depth += 1
            deepest = max(deepest, depth)
            lock.unlock()
            body()
            lock.lock()
            depth -= 1
            lock.unlock()
        }

        var count: Int {
            lock.lock()
            defer { lock.unlock() }
            return entries
        }
    }

    func testEveryStoreCallRunsInsideTheHold() throws {
        let counter = Counter()
        MLSClient.holdSuspension { counter.run($0) }
        XCTAssertTrue(MLSClient.holdsSuspension)

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("PeachyMLSHold-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let store = directory.appendingPathComponent("held.sqlite").path

        let issuer = try TestIssuer()
        var before = counter.count
        let client = try issuer.client(
            actorId: "actor-held", deviceId: "device-held", tag: 7, storePath: store)
        XCTAssertGreaterThan(counter.count, before, "the open ran unheld")

        before = counter.count
        try client.createGroup(id: Data("held-group".utf8))
        XCTAssertEqual(counter.count, before + 1, "a write ran unheld")

        before = counter.count
        _ = try client.epoch(groupID: Data("held-group".utf8))
        XCTAssertEqual(counter.count, before + 1, "a read ran unheld")

        before = counter.count
        XCTAssertThrowsError(try client.epoch(groupID: Data("no-such-group".utf8))) { error in
            XCTAssertEqual((error as? MLSError)?.code, .noSuchGroup, "the error came out changed")
        }
        XCTAssertEqual(counter.count, before + 1)

        before = counter.count
        client.close()
        XCTAssertEqual(counter.count, before + 1, "close (the last connection's checkpoint) ran unheld")
        XCTAssertThrowsError(try client.epoch(groupID: Data("held-group".utf8))) { error in
            XCTAssertEqual(error as? MLSError, .closed)
        }

        before = counter.count
        do {
            _ = try issuer.client(
                actorId: "actor-held", deviceId: "device-held", tag: 7, storePath: store)
        }
        // Open and deinit: two passes.
        XCTAssertEqual(counter.count, before + 2, "deinit freed the store unheld")
    }
}
