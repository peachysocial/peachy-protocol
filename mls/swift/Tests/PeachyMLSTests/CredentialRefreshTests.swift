// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// Renewing a seated leaf's credential, through the Swift wrapper.
///
/// The Rust twin is `mls/core/tests/credential_refresh.rs`, which drives a
/// settable clock through 100+ days; this one runs on the real clock, so it
/// mints a leaf that is already inside the refresh window instead.
/// docs/identity.md §Refreshing a seated leaf.
final class CredentialRefreshTests: XCTestCase {
    private let group = Data("peachy-credential-refresh".utf8)
    private let day: Int64 = 24 * 3_600

    func testALeafNearExpiryRenewsAndTheOtherMemberFollows() throws {
        let issuer = try TestIssuer(seed: 73)
        let adaSeed = TestIssuer.deviceSeed(31)
        func mint(_ actor: String, _ expiresAt: Int64) throws -> Data {
            try issuer.credential(
                actorId: actor, deviceId: "device-ada", deviceSeed: adaSeed, expiresAt: expiresAt
            )
        }
        let ada = try MLSClient(
            credential: try mint("actor-ada", TestIssuer.now + 5 * day),
            signatureSeed: adaSeed,
            trustedKeysJSON: issuer.trustedKeysJSON,
            storePath: nil,
            ownAccountIdentity: try TestIssuer.heldIdentity(actorId: "actor-ada")
        )
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 32)

        try ada.createGroup(id: group)
        let added = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(added.welcome))

        // Expiring, and nothing fresher in hand: the cue to call RegisterDevice.
        XCTAssertTrue(try ada.leafCredentialExpiring(groupID: group))
        XCTAssertFalse(try ada.credentialRefreshDue(groupID: group))
        XCTAssertFalse(try ada.leafCredentialPastGrace(groupID: group))
        XCTAssertFalse(try bo.leafCredentialExpiring(groupID: group))
        XCTAssertLessThanOrEqual(
            try ada.ownLeafCredentialExpiresAt(groupID: group), TestIssuer.now + 5 * day
        )

        // Another seat's credential on the same key is a policy refusal.
        let otherSeat = try issuer.credential(
            actorId: "actor-ada", deviceId: "device-ada-laptop", deviceSeed: adaSeed,
            expiresAt: TestIssuer.now + 30 * day
        )
        XCTAssertThrowsError(try ada.updateCredential(otherSeat, ownAccountIdentity: nil)) {
            XCTAssertEqual(($0 as? MLSError)?.code, .policyRefused)
        }
        // Somebody else's is certified under their account key, not the one
        // ada holds, and is refused before the seat is even compared.
        XCTAssertThrowsError(try ada.updateCredential(try mint("actor-eve", TestIssuer.now + 30 * day), ownAccountIdentity: nil)) {
            XCTAssertEqual(($0 as? MLSError)?.code, .credentialRejected)
        }
        // An older one is refused and changes nothing.
        XCTAssertThrowsError(try ada.updateCredential(try mint("actor-ada", TestIssuer.now + 2 * day), ownAccountIdentity: nil))
        XCTAssertFalse(try ada.credentialRefreshDue(groupID: group))

        let fresh = TestIssuer.now + 30 * day
        try ada.updateCredential(try mint("actor-ada", fresh), ownAccountIdentity: nil)
        XCTAssertTrue(try ada.credentialRefreshDue(groupID: group))

        let renewal = try ada.refreshCredential(groupID: group)
        XCTAssertNil(renewal.welcome, "a renewal welcomes nobody")
        XCTAssertEqual(try ada.mergePendingCommit(groupID: group), renewal.epoch)
        guard case .commit = try bo.processCommit(groupID: group, message: renewal.commit) else {
            return XCTFail("bo should have seen ada's renewal as a commit")
        }
        XCTAssertEqual(try bo.epoch(groupID: group), renewal.epoch)
        XCTAssertFalse(try ada.leafCredentialExpiring(groupID: group))
        XCTAssertGreaterThan(try ada.ownLeafCredentialExpiresAt(groupID: group), TestIssuer.now + 29 * day)

        let hello = try ada.encrypt(groupID: group, plaintext: Data("renewed".utf8))
        guard case let .application(heard, _, _) = try bo.processMessage(groupID: group, message: hello)
        else {
            return XCTFail("bo should have read an application message")
        }
        XCTAssertEqual(heard, Data("renewed".utf8))
    }
}
