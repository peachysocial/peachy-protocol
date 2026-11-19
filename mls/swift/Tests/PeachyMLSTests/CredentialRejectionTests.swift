// SPDX-License-Identifier: MIT
import Foundation
import XCTest
@testable import PeachyMLS

/// The Swift side of the rejection codes the core pins in
/// `mls/core/src/error.rs`.
///
/// Every reader in `MLSClient` decodes a code with
/// `CredentialRejection(rawValue:) ?? .malformed`, so a code this enum lacks
/// is not a crash and not a compile error — it is a leaf refused for the wrong
/// reason: an enum that stopped at 8 would read a credential claiming a
/// lifetime no issuer gives (10) as "the credential did not parse". 9 is
/// retired and must stay absent.
/// `CredentialsFixtureTests` holds the fixture's names to their numbers; this
/// holds the numbers to the enum the app actually switches on.
final class CredentialRejectionTests: XCTestCase {
    func testCodeTenDecodesToItsOwnCaseAndNineIsRetired() {
        XCTAssertNil(CredentialRejection(rawValue: 9))
        XCTAssertEqual(CredentialRejection(rawValue: 10), .implausibleLifetime)
    }

    func testEveryCodeTheFixtureUsesDecodesAndNothingFallsBackToMalformed() throws {
        let root = try CredentialsFixture.load()
        let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
        var reached = Set<UInt32>()
        for testCase in cases {
            guard let expect = testCase["expect"] as? [String: Any],
                  let code = expect["reasonCode"] as? Int
            else { continue }
            let id = testCase["id"] as? String ?? "<no id>"
            let decoded = try XCTUnwrap(
                CredentialRejection(rawValue: UInt32(code)),
                "case \(id): code \(code) is missing from the Swift enum, so a reader reports it as .malformed"
            )
            XCTAssertEqual(decoded.rawValue, UInt32(code))
            reached.insert(UInt32(code))
        }
        // The fixture reaches every code the core has (its own tests prove
        // that); the enum must have exactly those and no stale extras.
        XCTAssertEqual(Set(CredentialRejection.allCases.map(\.rawValue)), reached)
        XCTAssertEqual(CredentialRejection.allCases.count, 12)
    }
}
