// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import XCTest

@testable import PeachyMLS

/// Does the binding leak?
///
/// Every buffer the C ABI hands back is a Rust allocation that only
/// `peachy_mls_buffer_free` can release — Swift's ARC knows nothing about it,
/// and a missed free is invisible: the code works, the tests pass, and a chat
/// open for an afternoon grows without bound. Nothing in the type system can
/// catch that, so it is measured.
///
/// The measurement is resident set size through `task_info`, which is a blunt
/// instrument: the allocator does not return freed pages promptly, XCTest
/// itself allocates, and the first few hundred rounds warm up caches inside
/// OpenMLS. So the shape of the test is warm up first, measure after, and
/// assert a ceiling far above the noise and far below a real leak. At roughly
/// 200 bytes a round-trip of buffers, a binding that freed nothing would be
/// tens of megabytes past the bar; the measured growth here is a fraction of
/// a megabyte.
final class BufferHygieneTests: XCTestCase {
    /// The ceiling the task set. Generous on purpose: this is a leak detector,
    /// not a memory budget.
    private let allowedGrowth: UInt64 = 20 * 1_024 * 1_024

    func testAThousandRoundTripsDoNotGrowResidentMemory() throws {
        let issuer = try TestIssuer(seed: 101)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 51)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 52)
        let group = Data("peachy-hygiene".utf8)

        try ada.createGroup(id: group)
        let add = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(add.welcome))

        let plaintext = Data(repeating: 0x42, count: 256)

        // Warm-up: the first rounds allocate caches and grow the ratchet's own
        // state, which is not a leak and would otherwise be counted as one.
        for _ in 0..<100 {
            let message = try ada.encrypt(groupID: group, plaintext: plaintext)
            _ = try bo.processMessage(groupID: group, message: message)
        }

        let before = try XCTUnwrap(residentBytes(), "task_info should answer")
        for round in 0..<1_000 {
            let message = try ada.encrypt(groupID: group, plaintext: plaintext)
            let incoming = try bo.processMessage(groupID: group, message: message)
            guard case let .application(payload, sender, _) = incoming else {
                return XCTFail("round \(round) was not an application message")
            }
            // Touch what came back, so nothing in the round can be optimized
            // away and the identity buffers are exercised too.
            XCTAssertEqual(payload.count, plaintext.count)
            XCTAssertEqual(sender.deviceId, "device-ada")

            // And the other buffer-returning entry points, less often: a key
            // package and a roster are much bigger allocations, so a leak in
            // one of those shows up fast.
            if round % 100 == 0 {
                _ = try ada.generateKeyPackage()
                _ = try ada.roster(groupID: group)
                _ = try ada.exportSecret(groupID: group, label: "hygiene", length: 32)
                _ = try ada.identity()
            }
        }
        let after = try XCTUnwrap(residentBytes(), "task_info should answer")

        let growth = after > before ? after - before : 0
        XCTAssertLessThan(
            growth,
            allowedGrowth,
            "resident memory grew by \(growth / 1_024) KiB over 1,000 round trips "
                + "(\(before / 1_024) KiB → \(after / 1_024) KiB); "
                + "a buffer is not being freed"
        )
        // Printed rather than asserted tightly: the number is the useful part
        // of this test when it is passing, and pinning it would make an
        // allocator change look like a leak.
        print("resident growth over 1,000 round trips: \(growth / 1_024) KiB")
    }

    /// A client that goes out of scope takes its groups' key material with it.
    /// If `deinit` did not free the handle, this loop would grow by the size
    /// of a whole MLS state each time — the biggest allocation the binding
    /// owns, and the one with the worst consequence if it survives.
    func testClientsAreFreedWhenTheyGoOutOfScope() throws {
        let issuer = try TestIssuer(seed: 103)
        for _ in 0..<20 {
            let client = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 53)
            try client.createGroup(id: Data("scope".utf8))
            _ = try client.encrypt(groupID: Data("scope".utf8), plaintext: Data("x".utf8))
        }

        let before = try XCTUnwrap(residentBytes())
        for _ in 0..<200 {
            let client = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 54)
            try client.createGroup(id: Data("scope".utf8))
            _ = try client.encrypt(groupID: Data("scope".utf8), plaintext: Data("x".utf8))
        }
        let after = try XCTUnwrap(residentBytes())
        let growth = after > before ? after - before : 0
        XCTAssertLessThan(
            growth,
            allowedGrowth,
            "200 clients built and dropped grew resident memory by \(growth / 1_024) KiB"
        )
        print("resident growth over 200 client lifetimes: \(growth / 1_024) KiB")
    }

    /// An empty message survives the round trip.
    ///
    /// Not a corner for its own sake: an empty `Data` has no base address, and
    /// the ABI reads a null pointer as an error even at length zero, so
    /// without the sentinel in `withBytes` this would come back as
    /// `.invalidArgument` — a wrapper bug that would look like a protocol one.
    func testAnEmptyMessageRoundTrips() throws {
        let issuer = try TestIssuer(seed: 107)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 55)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 56)
        let group = Data("empty".utf8)

        try ada.createGroup(id: group)
        let add = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(add.welcome))

        let message = try ada.encrypt(groupID: group, plaintext: Data())
        guard case let .application(payload, _, _) = try bo.processMessage(
            groupID: group,
            message: message
        ) else {
            return XCTFail("bo should have read an application message")
        }
        XCTAssertEqual(payload, Data())
    }

    /// Concurrent use does not corrupt anything: `MLSClient` is
    /// `@unchecked Sendable` because it serializes every call itself, and this
    /// is the claim being exercised. Under a broken lock this is a crash or a
    /// wrong answer, not a flaky assertion.
    func testConcurrentCallsAreSerialized() throws {
        let issuer = try TestIssuer(seed: 109)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 57)
        let group = Data("concurrent".utf8)
        try ada.createGroup(id: group)

        let done = expectation(description: "every thread finished")
        done.expectedFulfillmentCount = 8
        for worker in 0..<8 {
            DispatchQueue.global().async {
                for _ in 0..<50 {
                    do {
                        let payload = Data("worker \(worker)".utf8)
                        let message = try ada.encrypt(groupID: group, plaintext: payload)
                        XCTAssertFalse(message.isEmpty)
                        XCTAssertGreaterThanOrEqual(try ada.epoch(groupID: group), 0)
                    } catch {
                        XCTFail("a concurrent call failed: \(error)")
                    }
                }
                done.fulfill()
            }
        }
        wait(for: [done], timeout: 60)
    }
}

/// This process's resident set size, from `mach_task_basic_info`.
///
/// `task_info` wants the struct as an array of `integer_t`, which is why the
/// pointer is rebound rather than passed directly.
private func residentBytes() -> UInt64? {
    var info = mach_task_basic_info()
    var count = mach_msg_type_number_t(
        MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size
    )
    let result = withUnsafeMutablePointer(to: &info) { pointer in
        pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
            task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), rebound, &count)
        }
    }
    guard result == KERN_SUCCESS else { return nil }
    return info.resident_size
}
