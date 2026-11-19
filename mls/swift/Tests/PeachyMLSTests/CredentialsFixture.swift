// SPDX-License-Identifier: MIT
import Foundation

/// `mls/fixtures/credentials.json`, read for the replay in
/// `CredentialsFixtureTests`.
///
/// Only the *loading* is here. The door is the one `RulesFixture.evaluate`
/// already wraps — `peachy_mls_fixture_evaluate_case`, behind the `fixture`
/// cargo feature and the `PEACHY_MLS_FIXTURE` C define — because a case says
/// which table it belongs to in its own `kind` field. A second C entry point
/// for the second fixture would have meant a second header `#if`, a second
/// Swift shim and a second place for a marshaling bug to hide, in order to
/// ask the same question about a different table.
///
/// **Test-only, like `RulesFixture`.** The xcframework the Apple apps link is
/// built without the feature, so the symbol is not even in the archive.
enum CredentialsFixture {
    /// `mls/fixtures/credentials.json`, resolved from THIS FILE's path.
    ///
    /// Not a SwiftPM `resources:` copy, for the reason spelled out on
    /// `RulesFixture.fixtureURL`: the fixture lives in `mls/fixtures/` because
    /// it belongs to four clients rather than to this one, SwiftPM refuses a
    /// resource path that escapes the target directory, and a copy under
    /// `Tests/` would be a second fixture pretending to be the first.
    static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)            // …/mls/swift/Tests/PeachyMLSTests/CredentialsFixture.swift
            .deletingLastPathComponent()           // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()           // …/mls/swift/Tests
            .deletingLastPathComponent()           // …/mls/swift
            .deletingLastPathComponent()           // …/mls
            .appendingPathComponent("fixtures/credentials.json")
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
}
