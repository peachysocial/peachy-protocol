// SPDX-License-Identifier: MIT
import Foundation

/// `mls/fixtures/device-link.json`, read for the replay in
/// `DeviceLinkFixtureTests`.
///
/// Only the *loading* is here. The door is the one `RulesFixture.evaluate`
/// already wraps — `peachy_mls_fixture_evaluate_case`, behind the `fixture`
/// cargo feature and the `PEACHY_MLS_FIXTURE` C define — because a case says
/// which table it belongs to in its own `kind` field. A third C entry point
/// for the third fixture would have meant a third header `#if`, a third Swift
/// shim and a third place for a marshaling bug to hide, in order to ask the
/// same question about a different table.
///
/// **Test-only, like `RulesFixture` and `CredentialsFixture`.** The
/// xcframework the Apple apps link is built without the feature, so the symbol
/// is not even in the archive. What an app links instead is
/// `MLSClient.deviceApprovalStatement`, `signDeviceApproval`,
/// `verifyDeviceApproval` and the `deviceLink…` calls, which are unconditional — and
/// which this replay also drives, since the fixture door reaches the same
/// derivation by another path and could agree with itself while the product
/// surface is wrong.
enum DeviceLinkFixture {
    /// `mls/fixtures/device-link.json`, resolved from THIS FILE's path.
    ///
    /// Not a SwiftPM `resources:` copy, for the reason spelled out on
    /// `RulesFixture.fixtureURL`: the fixture lives in `mls/fixtures/` because
    /// it belongs to four clients rather than to this one, SwiftPM refuses a
    /// resource path that escapes the target directory, and a copy under
    /// `Tests/` would be a second fixture pretending to be the first.
    static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)            // …/mls/swift/Tests/PeachyMLSTests/DeviceLinkFixture.swift
            .deletingLastPathComponent()           // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()           // …/mls/swift/Tests
            .deletingLastPathComponent()           // …/mls/swift
            .deletingLastPathComponent()           // …/mls
            .appendingPathComponent("fixtures/device-link.json")
    }

    /// The fixture as a top-level JSON object.
    static func load() throws -> [String: Any] {
        let url = fixtureURL
        guard let data = try? Data(contentsOf: url),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw RulesFixture.Failure.fixtureUnreadable(url.path)
        }
        return root
    }

    /// One case in, one verdict out — `RulesFixture.evaluate`, named here so a
    /// reader of this replay is not sent looking for a door that does not
    /// exist.
    static func evaluate(case object: [String: Any]) throws -> String {
        try RulesFixture.evaluate(case: object)
    }

    static func evaluate(caseJSON: String) throws -> String {
        try RulesFixture.evaluate(caseJSON: caseJSON)
    }

    /// Hex text from the fixture as bytes.
    ///
    /// The fixture writes every key, statement and signature in hex because
    /// JSON has no byte string, and every binding had to agree on one
    /// spelling. This is the Swift end of that; the strictness is deliberate,
    /// since a silently truncated string would become different bytes and
    /// therefore a different, wrong, golden value.
    static func bytes(_ hex: String) -> Data {
        var out = Data(capacity: hex.count / 2)
        var high: UInt8?
        for character in hex {
            guard let digit = character.hexDigitValue else { return Data() }
            let value = UInt8(digit)
            if let first = high {
                out.append(first << 4 | value)
                high = nil
            } else {
                high = value
            }
        }
        return high == nil ? out : Data()
    }

    /// Bytes as lowercase hex, for comparing against a fixture's golden value.
    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
