// SPDX-License-Identifier: MIT
import Foundation
import PeachyMLSCore

@testable import PeachyMLS

/// The golden policy fixture, reached through the C door that
/// `mls/cabi/src/lib.rs` exposes behind the `fixture` cargo feature.
///
/// **Test-only, and deliberately not in the `PeachyMLS` product.** The header
/// declares `peachy_mls_fixture_evaluate_case` inside
/// `#if defined(PEACHY_MLS_FIXTURE)` and only this test target defines it
/// (Package.swift), so a stray call from `Sources/PeachyMLS` would not
/// compile — and the xcframework the apps link is built without the feature,
/// so the symbol is not even in the archive. An app has no use for a JSON
/// replay harness; what it uses is the policy, which is inside the core on the
/// other side of every one of these calls.
///
/// ## Why there is no Swift model of a case
///
/// A case object goes in as the bytes it was read as, and a verdict comes back
/// as bytes. Decoding a case into a Swift struct and re-encoding it would be a
/// second opinion about the fixture's shape, held by one client — which is the
/// exact failure the fixture exists to prevent. `JSONSerialization` is used
/// only to compare the verdict with the case's own `expect`, where an
/// object-to-object comparison is the point: a string comparison would fail on
/// key order that means nothing.
enum RulesFixture {
    enum Failure: Error, CustomStringConvertible {
        /// The door refused the case — an unknown kind, sender or `call`. NOT
        /// a verdict, and never to be turned into one.
        case refused(Int32, String)
        case emptyVerdict
        case fixtureUnreadable(String)

        var description: String {
            switch self {
            case let .refused(code, message): return "the fixture door refused it (\(code)): \(message)"
            case .emptyVerdict: return "the fixture door returned an empty verdict"
            case let .fixtureUnreadable(path): return "could not read \(path)"
            }
        }
    }

    /// `mls/fixtures/rules.json`, resolved from THIS FILE's path.
    ///
    /// Not a SwiftPM `resources:` copy, and the difference matters. A resource
    /// would have to be declared as a path inside the package directory, and
    /// the fixture lives one level up in `mls/fixtures/` because it belongs to
    /// four clients rather than to this one; SwiftPM refuses a resource path
    /// that escapes the target directory, so the only way to have one would be
    /// to COPY the file — a second fixture pretending to be the first, which
    /// is worse than no replay at all. `#filePath` is absolute, is fixed at
    /// compile time, and is independent of the working directory `swift test`
    /// happens to be run from.
    static var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)            // …/mls/swift/Tests/PeachyMLSTests/RulesFixture.swift
            .deletingLastPathComponent()           // …/mls/swift/Tests/PeachyMLSTests
            .deletingLastPathComponent()           // …/mls/swift/Tests
            .deletingLastPathComponent()           // …/mls/swift
            .deletingLastPathComponent()           // …/mls
            .appendingPathComponent("fixtures/rules.json")
    }

    /// The fixture as a top-level JSON object.
    static func load() throws -> [String: Any] {
        let url = fixtureURL
        guard let data = try? Data(contentsOf: url),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw Failure.fixtureUnreadable(url.path)
        }
        return root
    }

    /// One case in, one verdict out — the same door, with the same signature,
    /// that Rust, JavaScript and Kotlin call.
    ///
    /// - Parameter caseJSON: the whole case object, `expect` and `why`
    ///   included. The door ignores them, so nothing has to be stripped first
    ///   and every client sends the bytes it read.
    /// - Returns: the verdict object as JSON text.
    /// - Throws: `Failure.refused` when the case names something that does not
    ///   exist. That is not a denial and must never be recorded as one.
    static func evaluate(caseJSON: String) throws -> String {
        var verdict = PeachyMlsBuffer()
        let status = caseJSON.withCString { text in
            peachy_mls_fixture_evaluate_case(text, &verdict)
        }
        guard status == PEACHY_MLS_OK else {
            throw Failure.refused(status, lastErrorMessage())
        }
        defer { peachy_mls_buffer_free(&verdict) }
        guard let bytes = verdict.data, verdict.len > 0 else {
            throw Failure.emptyVerdict
        }
        // The buffer carries its own length and is not NUL-terminated, like
        // every other buffer in this ABI.
        return String(decoding: Data(bytes: bytes, count: Int(verdict.len)), as: UTF8.self)
    }

    /// Evaluate a case given as a dictionary read out of the fixture, by
    /// re-serializing exactly what was read.
    ///
    /// `.sortedKeys` is here so the bytes handed to the door are stable run to
    /// run; the door does not care about key order, and neither does anything
    /// downstream, but a failure message that changed shape between runs would
    /// be harder to read than one that does not.
    static func evaluate(case object: [String: Any]) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return try evaluate(caseJSON: String(decoding: data, as: UTF8.self))
    }
}
