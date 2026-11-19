// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// A failure has to arrive in Swift as something a person can read.
///
/// A binding that collapses every error to `-1`/null is the specific thing
/// this file refuses to let happen: a thrown `MLSError`
/// must carry the code the ABI returned AND the sentence it left in the
/// thread-local slot. An empty message here would mean the binding read the
/// slot too late — after another call had cleared it — which is exactly the
/// bug a test that only checks the code would never see.
final class ErrorSurfaceTests: XCTestCase {
    func testABadCredentialThrowsWithANonEmptyMessage() throws {
        let issuer = try TestIssuer(seed: 71)
        let junk = Data("pdc1.not-a-real-token.nope".utf8)

        XCTAssertThrowsError(
            try MLSClient(
                credential: junk,
                signatureSeed: TestIssuer.deviceSeed(9),
                trustedKeysJSON: issuer.trustedKeysJSON,
                storePath: nil,
                ownAccountIdentity: try TestIssuer.heldIdentity(actorId: "actor-ada")
            )
        ) { error in
            guard let mlsError = error as? MLSError else {
                return XCTFail("expected an MLSError, got \(error)")
            }
            XCTAssertEqual(mlsError.code, .credentialRejected)
            XCTAssertFalse(
                mlsError.message.isEmpty,
                "a code without a message cannot be acted on"
            )
            // The message names the check that failed rather than restating
            // the code.
            XCTAssertFalse(mlsError.description.isEmpty)
        }
    }

    /// An expired credential is refused, and the message says so — the one
    /// rejection a client will actually meet in the field, when a device has
    /// been offline past its credential's `exp`.
    func testAnExpiredCredentialNamesExpiry() throws {
        let issuer = try TestIssuer(seed: 73)
        let now = TestIssuer.now
        XCTAssertThrowsError(
            try issuer.client(
                actorId: "actor-ada",
                deviceId: "device-ada",
                tag: 11,
                issuedAt: now - 40 * 24 * 3_600,
                expiresAt: now - 24 * 3_600
            )
        ) { error in
            let mlsError = error as? MLSError
            XCTAssertEqual(mlsError?.code, .credentialRejected)
            XCTAssertTrue(
                mlsError?.message.lowercased().contains("expired") == true,
                "expected the message to name expiry, got \(mlsError?.message ?? "nothing")"
            )
        }
    }

    /// A seed that is not the credential's device key is the forgery case:
    /// rule 5 of `docs/mls-core.md` §The leaf credential is a Peachy device
    /// credential. It must fail at construction, not at the first commit.
    func testACredentialForSomebodyElsesKeyIsRefused() throws {
        let issuer = try TestIssuer(seed: 79)
        let token = try issuer.credential(
            actorId: "actor-ada",
            deviceId: "device-ada",
            deviceSeed: TestIssuer.deviceSeed(21)
        )
        XCTAssertThrowsError(
            try MLSClient(
                credential: token,
                // A different device's seed entirely.
                signatureSeed: TestIssuer.deviceSeed(22),
                trustedKeysJSON: issuer.trustedKeysJSON,
                storePath: nil,
                ownAccountIdentity: try TestIssuer.heldIdentity(actorId: "actor-ada")
            )
        ) { error in
            XCTAssertEqual((error as? MLSError)?.code, .credentialRejected)
            XCTAssertFalse((error as? MLSError)?.message.isEmpty ?? true)
        }
    }

    /// A seed of the wrong length is caught before anything cryptographic, and
    /// arrives as `.invalidArgument` rather than as a credential rejection —
    /// the distinction matters, because one is a bug in the caller and the
    /// other is a fact about the credential.
    func testAShortSeedIsAnInvalidArgument() throws {
        let issuer = try TestIssuer(seed: 83)
        let token = try issuer.credential(
            actorId: "actor-ada",
            deviceId: "device-ada",
            deviceSeed: TestIssuer.deviceSeed(31)
        )
        XCTAssertThrowsError(
            try MLSClient(
                credential: token,
                signatureSeed: Data(repeating: 0, count: 16),
                trustedKeysJSON: issuer.trustedKeysJSON,
                storePath: nil,
                ownAccountIdentity: try TestIssuer.heldIdentity(actorId: "actor-ada")
            )
        ) { error in
            XCTAssertEqual((error as? MLSError)?.code, .invalidArgument)
            XCTAssertTrue(
                (error as? MLSError)?.message.contains("32 bytes") == true,
                "the message should say what the right length is"
            )
        }
    }

    func testAGroupNobodyOpenedIsNoSuchGroup() throws {
        let issuer = try TestIssuer(seed: 89)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 41)
        XCTAssertThrowsError(try ada.epoch(groupID: Data("never-created".utf8))) { error in
            XCTAssertEqual((error as? MLSError)?.code, .noSuchGroup)
            XCTAssertFalse((error as? MLSError)?.message.isEmpty ?? true)
        }
    }

    /// Garbage bytes are a codec error, not a crash — a delivery service can
    /// and will hand a client something it cannot parse.
    func testGarbageIsACodecErrorAndNotACrash() throws {
        let issuer = try TestIssuer(seed: 97)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 43)
        let group = Data("garbage".utf8)
        try ada.createGroup(id: group)

        XCTAssertThrowsError(
            try ada.processMessage(groupID: group, message: Data(repeating: 0xEE, count: 64))
        ) { error in
            guard let mlsError = error as? MLSError else {
                return XCTFail("expected an MLSError, got \(error)")
            }
            XCTAssertTrue(
                [.codec, .mls].contains(mlsError.code),
                "expected a decode failure, got \(mlsError.code)"
            )
            XCTAssertFalse(mlsError.message.isEmpty)
        }
    }

    /// Every status code round-trips through `MLSError.Code`, and a number the
    /// binding has never heard of survives as `.other` instead of trapping.
    func testEveryStatusCodeRoundTrips() {
        for raw: Int32 in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19, 20, 21, 22, 23, 99] {
            XCTAssertNotEqual(MLSError.Code(raw), .other(raw), "status \(raw) has no case")
            XCTAssertEqual(MLSError.Code(raw).rawValue, raw)
        }
        XCTAssertEqual(MLSError.Code(4242), .other(4242))
        XCTAssertEqual(MLSError.Code(4242).description, "unknown(4242)")
    }
}
