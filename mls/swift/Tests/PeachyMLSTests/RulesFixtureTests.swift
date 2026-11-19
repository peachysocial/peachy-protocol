// SPDX-License-Identifier: MIT
import Foundation
import XCTest

/// The golden rules fixture, replayed through the C door from Swift.
///
/// `mls/fixtures/rules.json` is the table of every decision Peachy's group
/// policy makes. `mls/core/tests/rules_fixture.rs` replays it in Rust and
/// `mls/wasm/tests/node/rules.test.mjs` replays it from JavaScript; this is the
/// Apple half, and the Android binding's `RulesFixtureTest` (not in this repository)
/// is the Android one. Same file, same door, every binding.
///
/// A replay per binding and not one, for the reason the journey has more than one: the
/// Rust replay proves the POLICY, and each binding's replay proves that
/// binding's DOOR. What can only go wrong here is the crossing — a verdict that
/// arrives with a trailing NUL and stops parsing, a `reasonCode` that lost its
/// number on the way through C, a refusal that reaches Swift as an empty string
/// instead of a thrown error. None of that is visible from Rust, and an Apple
/// client shipping a policy that disagrees with the other three is exactly what
/// docs/mls-core.md §Golden rules fixture exists to prevent.
///
/// The fixture is READ, never copied: `RulesFixture.fixtureURL` resolves
/// `mls/fixtures/rules.json` from `#filePath`. A copy under `Tests/` would be a
/// second fixture pretending to be the first, which is worse than no replay.
final class RulesFixtureTests: XCTestCase {
    /// The format version this replay understands — the same equality
    /// `peachy_mls_core::fixture::FORMAT_VERSION` and the JavaScript replay
    /// assert from their own ends. A case whose SHAPE changed is not something
    /// to read past in any language.
    private let formatVersion = 1

    private func cases() throws -> [[String: Any]] {
        let root = try RulesFixture.load()
        return try XCTUnwrap(root["cases"] as? [[String: Any]], "`cases` is an array of objects")
    }

    func testTheFixtureIsTheFormatThisBuildReads() throws {
        let root = try RulesFixture.load()
        XCTAssertEqual(
            root["version"] as? Int, formatVersion,
            "the fixture's format version and this replay disagree"
        )
        // A floor, deliberately under today's count, so a replay that stopped
        // finding cases cannot read as a clean pass over nothing — the failure
        // this whole file exists to make impossible.
        XCTAssertGreaterThanOrEqual(
            try cases().count, 50,
            "the fixture shrank or stopped parsing"
        )
    }

    func testEveryCaseGetsTheVerdictItExpectsThroughTheCDoor() throws {
        var failures: [String] = []
        var ids = Set<String>()
        let all = try cases()

        for testCase in all {
            let id = testCase["id"] as? String ?? "<no id>"
            XCTAssertFalse(ids.contains(id), "two cases share the id \(id)")
            ids.insert(id)

            // The whole case object goes over, `expect` and `why` included and
            // ignored — exactly what the other three replays hand to the same
            // door, so a difference between two clients is a difference in a
            // BINDING and can never be a difference in what was asked.
            let verdictText = try RulesFixture.evaluate(case: testCase)
            let verdict = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(verdictText.utf8)) as? [String: Any],
                "case \(id): a verdict is a JSON object; got \(verdictText)"
            )
            let expected = try XCTUnwrap(
                testCase["expect"] as? [String: Any], "case \(id) has no `expect`"
            )

            // Whole-object equality, not field by field: an EXTRA key in the
            // verdict — a `reason` on an allow, say — is a disagreement too,
            // and it is the kind a per-field check reads straight past.
            if NSDictionary(dictionary: verdict) != NSDictionary(dictionary: expected) {
                failures.append("  \(id)\n    expected \(expected)\n    actual   \(verdict)")
            }
        }

        XCTAssertTrue(
            failures.isEmpty,
            """
            \(failures.count) of \(all.count) fixture cases disagree with the policy as the \
            Swift binding reports it.
            Either mls/core/src/rules.rs changed a decision — in which case every client changed \
            with it and the fixture is the record of that — or the fixture is wrong.
            \(failures.joined(separator: "\n"))
            """
        )
    }

    func testAnAllowCarriesNoReasonAndADenialCarriesBothTheNameAndTheNumber() throws {
        // Spot checks written out in Swift rather than read from the file, so
        // that a fixture which somehow round-trips its own mistakes still fails
        // here.
        try assertVerdict(
            #"{"call":"evaluate","proposal":{"kind":"add","sender":"member"}}"#,
            is: ["decision": "allow"]
        )
        try assertVerdict(
            #"{"call":"evaluate","proposal":{"kind":"external_init","sender":"member"}}"#,
            is: ["decision": "deny", "reason": "external_join", "reasonCode": 1]
        )
        try assertVerdict(
            #"{"call":"evaluateCommitSender","sender":"new_member_commit"}"#,
            is: ["decision": "deny", "reason": "external_join", "reasonCode": 1]
        )
        // `reasonCode` is a NUMBER after the crossing and not a string. It is
        // half of what makes this contract catch a renumbering that left a name
        // alone, and JSON through a C buffer is where a number quietly becomes
        // text.
        let denial = try RulesFixture.evaluate(
            caseJSON: #"{"call":"evaluate","proposal":{"kind":"reinit","sender":"member"}}"#
        )
        let parsed = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(denial.utf8)) as? [String: Any]
        )
        XCTAssertEqual(parsed["reasonCode"] as? Int, 5)
    }

    func testACaseThatAddressesNothingRealThrowsRatherThanReturningAVerdict() throws {
        // The distinction the whole replay rests on. A case naming a proposal
        // kind that no longer exists has to fail loudly — the alternative is a
        // fixture that goes on passing while it tests nothing.
        XCTAssertThrowsError(
            try RulesFixture.evaluate(
                caseJSON: #"{"call":"evaluate","proposal":{"kind":"teleport","sender":"member"}}"#
            )
        ) { error in
            let message = String(describing: error)
            XCTAssertTrue(
                message.contains("teleport"),
                "the failure must name what it could not find: \(message)"
            )
            // And it lists what IS known, so repointing a case is a read rather
            // than a search.
            XCTAssertTrue(message.contains("external_init"), message)
        }

        XCTAssertThrowsError(
            try RulesFixture.evaluate(caseJSON: #"{"call":"evaluateNothing"}"#)
        ) { error in
            XCTAssertTrue(String(describing: error).contains("evaluateNothing"))
        }

        XCTAssertThrowsError(try RulesFixture.evaluate(caseJSON: "{not json")) { error in
            XCTAssertTrue(
                String(describing: error).contains("could not read the fixture case"),
                String(describing: error)
            )
        }
    }

    func testTheRulesBlockTravelsWithTheCase() throws {
        // `allowRemoveByAnyMember` is the one knob of the proposal rules,
        // so the fixture has to be able to describe both
        // settings — and the binding has to carry the block across. A door that
        // dropped it would answer every case correctly today and answer them
        // all wrongly the day the default flips.
        try assertVerdict(
            """
            {"call":"evaluate","rules":{"allowRemoveByAnyMember":false},\
            "proposal":{"kind":"remove","sender":"member"}}
            """,
            is: ["decision": "deny", "reason": "non_member_proposal", "reasonCode": 3]
        )
        try assertVerdict(
            #"{"call":"evaluate","proposal":{"kind":"remove","sender":"member"}}"#,
            is: ["decision": "allow"]
        )
    }

    private func assertVerdict(
        _ caseJSON: String,
        is expected: [String: Any],
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let text = try RulesFixture.evaluate(caseJSON: caseJSON)
        let actual = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
            "a verdict is a JSON object; got \(text)",
            file: file, line: line
        )
        XCTAssertEqual(
            NSDictionary(dictionary: actual), NSDictionary(dictionary: expected),
            file: file, line: line
        )
    }
}
