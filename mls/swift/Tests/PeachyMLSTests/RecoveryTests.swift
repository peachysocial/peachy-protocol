// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import PeachyMLSCore
import XCTest

@testable import PeachyMLS

/// GROUP RECOVERY through the wrapper the two Apple apps link
/// (docs/mls-core.md §Group recovery). `mls/core/tests/recovery.rs` holds the
/// rules; this holds the binding: the stale-copy code arrives as its own
/// case, the steps come back as the enum, and the drain's owed list decodes.
final class RecoveryTests: XCTestCase {
    private let group = Data("peachy-swift-recovery".utf8)

    private func head(of member: MLSClient) throws -> (epoch: UInt64, verifier: Data) {
        let key = try member.exportSecret(
            groupID: group, label: "peachy sealed-sender v1", context: group, length: 32
        )
        return (try member.epoch(groupID: group), Data(SHA256.hash(data: key)))
    }

    func testAStaleCopyIsToldToRejoin() throws {
        let issuer = try TestIssuer(seed: 93)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 31)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 32)
        try ada.createGroup(id: group)
        let add = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        let seated = try head(of: ada)
        _ = try bo.join(
            welcome: try XCTUnwrap(add.welcome), headEpoch: seated.epoch,
            headVerifier: seated.verifier)

        // Level: in step.
        XCTAssertEqual(try bo.recoveryBegin(groupID: group), .readHead)
        XCTAssertEqual(
            try bo.recoveryJudge(
                groupID: group, kind: .check, headEpoch: seated.epoch,
                headVerifier: seated.verifier, fresh: true, nowMs: 1_000),
            .inStep)

        // Ada moves on without Bo and seals past him.
        _ = try ada.selfUpdate(groupID: group)
        try ada.mergePendingCommit(groupID: group)
        let sealed = try ada.encrypt(groupID: group, plaintext: Data("your turn".utf8))
        XCTAssertThrowsError(try bo.processMessage(groupID: group, message: sealed)) { error in
            XCTAssertEqual((error as? MLSError)?.code, .staleCopy)
            XCTAssertTrue((error as? MLSError)?.message.hasPrefix("stale copy") ?? false)
        }

        XCTAssertTrue(try bo.recoveryReadDue(groupID: group, sealedAhead: true, nowMs: 2_000))
        XCTAssertFalse(try bo.recoveryReadDue(groupID: group, sealedAhead: true, nowMs: 2_001))
        let ahead = try head(of: ada)
        XCTAssertEqual(try bo.recoveryBegin(groupID: group), .readHead)
        let step = try bo.recoveryJudge(
            groupID: group, kind: .sealedAhead, headEpoch: ahead.epoch,
            headVerifier: ahead.verifier, fresh: true, nowMs: 2_000)
        XCTAssertEqual(step, .rejoinStuck)
        XCTAssertTrue(step.rejoins)
        XCTAssertEqual(
            try bo.recoveryDrainComplete(startedAtMs: 3_000, evidence: true, nowMs: 3_000), [])

        // No head at all is no verdict, and the raw values are the header's.
        XCTAssertEqual(try bo.recoveryBegin(groupID: group), .readHead)
        XCTAssertEqual(
            try bo.recoveryJudge(
                groupID: group, kind: .check, headEpoch: nil, headVerifier: Data(), fresh: true,
                nowMs: 4_000),
            .inStep)
        XCTAssertEqual(MLSClient.RecoveryStep.settleFirst.rawValue, UInt32(PEACHY_MLS_RECOVERY_SETTLE_FIRST))
        XCTAssertEqual(MLSClient.HeadReadKind.lost.rawValue, UInt32(PEACHY_MLS_HEAD_READ_LOST))
        XCTAssertEqual(MLSError.Code(PEACHY_MLS_ERR_STALE_COPY), .staleCopy)
    }
}
