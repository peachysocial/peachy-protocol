// SPDX-License-Identifier: MIT
import Foundation
import XCTest

/// The golden credential fixture, replayed through the C door from Swift.
///
/// `mls/fixtures/credentials.json` is the table of every way a `pdc1` device
/// credential can fail to make a leaf into somebody.
/// `mls/core/tests/credentials_fixture.rs` replays it in Rust,
/// `mls/wasm/tests/node/credentials.test.mjs` from JavaScript and
/// the Android binding's `CredentialsFixtureTest` (not in this repository) from
/// Kotlin; this is the Apple half. Same file, same door, every binding — the
/// sibling of `RulesFixtureTests`, and the second half of what
/// docs/mls-core.md §Golden credential fixture asks of every client
/// before it ships.
///
/// A replay per binding and not one, because the Rust replay proves the VERIFIER and
/// each binding's replay proves that binding's DOOR. What can only go wrong
/// here is the crossing: a verdict that lost its tail because the C buffer is
/// not NUL-terminated and something assumed it was, a `reasonCode` or an
/// `expiresAt` that arrived as text, a refusal that reached Swift as an empty
/// string instead of a thrown error. None of that is visible from Rust, and an
/// Apple client that believed a leaf the other three refused is the exact
/// failure this fixture exists to make impossible.
final class CredentialsFixtureTests: XCTestCase {
    /// The format version this replay understands — the same equality
    /// `peachy_mls_core::fixture::FORMAT_VERSION` and the other three replays
    /// assert from their own ends.
    private let formatVersion = 1

    /// Every `CredentialRejection`, spelled out in Swift rather than read from
    /// the file, so a fixture that quietly stopped covering one of them still
    /// fails here. The numbers are half the contract: a rename that left the
    /// discriminant alone and a renumbering that left the name alone are the
    /// two ways it breaks.
    private let rejections: [String: Int] = [
        "malformed": 1,
        "unknown_kid": 2,
        "bad_signature": 3,
        "expired": 4,
        "not_yet_valid": 5,
        "leaf_key_mismatch": 6,
        "unsupported_version": 7,
        "wrong_credential_type": 8,
        "implausible_lifetime": 10,
        "account_signature": 11,
        "not_approved": 12,
        "not_own_account_key": 13,
    ]

    private func cases() throws -> [[String: Any]] {
        let root = try CredentialsFixture.load()
        return try XCTUnwrap(root["cases"] as? [[String: Any]], "`cases` is an array of objects")
    }

    func testTheFixtureIsTheFormatThisBuildReads() throws {
        let root = try CredentialsFixture.load()
        XCTAssertEqual(
            root["version"] as? Int, formatVersion,
            "the fixture's format version and this replay disagree"
        )
        // A floor, deliberately under today's count, so a replay that stopped
        // finding cases cannot read as a clean pass over nothing.
        XCTAssertGreaterThanOrEqual(try cases().count, 35, "the fixture shrank or stopped parsing")

        // Every case says which table it belongs to. An absent `kind` means
        // `rules` at the door, which is what keeps rules.json working
        // unchanged — and what would send a credential case to the policy
        // layer.
        for testCase in try cases() {
            XCTAssertEqual(
                testCase["kind"] as? String, "credential",
                "case \(testCase["id"] ?? "<no id>") has no kind: \"credential\""
            )
        }
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
            let verdictText = try CredentialsFixture.evaluate(case: testCase)
            let verdict = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(verdictText.utf8)) as? [String: Any],
                "case \(id): a verdict is a JSON object; got \(verdictText)"
            )
            let expected = try XCTUnwrap(
                testCase["expect"] as? [String: Any], "case \(id) has no `expect`"
            )

            // Whole-object equality, not field by field: an EXTRA key in the
            // verdict — a `reason` on an acceptance, say — is a disagreement
            // too, and it is the kind a per-field check reads straight past.
            if NSDictionary(dictionary: verdict) != NSDictionary(dictionary: expected) {
                failures.append("  \(id)\n    expected \(expected)\n    actual   \(verdict)")
            }
        }

        XCTAssertTrue(
            failures.isEmpty,
            """
            \(failures.count) of \(all.count) fixture cases disagree with the identity layer as \
            the Swift binding reports it.
            Either mls/core/src/identity.rs or mls/core/src/credential.rs changed a decision — in \
            which case every client changed with it and the fixture is the record of that — or \
            the fixture is wrong.
            \(failures.joined(separator: "\n"))
            """
        )
    }

    func testAllTenRejectionCodesAreReachedAndEveryNameIsOneOfThem() throws {
        let all = try cases()
        let reached = Set(all.compactMap { ($0["expect"] as? [String: Any])?["reason"] as? String })
        let missing = rejections.keys.filter { !reached.contains($0) }.sorted()
        XCTAssertTrue(
            missing.isEmpty,
            """
            no case produces \(missing.joined(separator: ", ")). A rejection nothing reaches is a \
            branch this fixture cannot protect, and it can go wrong in one client with nothing \
            going red.
            """
        )

        for testCase in all {
            guard let expect = testCase["expect"] as? [String: Any],
                  let reason = expect["reason"] as? String
            else { continue }
            let id = testCase["id"] as? String ?? "<no id>"
            let code = try XCTUnwrap(rejections[reason], "case \(id): no such rejection \(reason)")
            XCTAssertEqual(expect["reasonCode"] as? Int, code, "case \(id): \(reason) is code \(code)")
        }
    }

    func testAnAcceptanceNamesWhoItAcceptedAndARejectionCarriesNameAndNumber() throws {
        // Spot checks written out in Swift rather than read from the file, so
        // that a fixture which somehow round-trips its own mistakes still fails
        // here. The seeds are the fixture's own: 07×32 is the Peachy server's
        // stand-in signing key, 11×32 is Ada's device, 22×32 an attacker's.
        let good = """
        {"kind":"credential","call":"validateToken","nowUnix":1789516800,
         "trust":["0707070707070707070707070707070707070707070707070707070707070707"],
         "mint":{"signerSeed":"0707070707070707070707070707070707070707070707070707070707070707",
                 "actorId":"actor-ada","deviceId":"device-ada-phone",
                 "deviceSeed":"1111111111111111111111111111111111111111111111111111111111111111",
                 "issuedAt":1789513200,"expiresAt":1792108800}}
        """
        try assertVerdict(
            good,
            is: [
                "decision": "accepted",
                "actorId": "actor-ada",
                "deviceId": "device-ada-phone",
                "kid": "fe812c12",
                "expiresAt": 1_792_108_800,
            ]
        )

        // The same credential replayed onto somebody else's leaf — the check
        // that gives the whole credential its meaning, and therefore the one
        // worth asserting twice.
        let replayed = """
        {"kind":"credential","call":"validateToken","nowUnix":1789516800,
         "trust":["0707070707070707070707070707070707070707070707070707070707070707"],
         "mint":{"signerSeed":"0707070707070707070707070707070707070707070707070707070707070707",
                 "actorId":"actor-ada","deviceId":"device-ada-phone",
                 "deviceSeed":"1111111111111111111111111111111111111111111111111111111111111111",
                 "issuedAt":1789513200,"expiresAt":1792108800},
         "leafSeed":"2222222222222222222222222222222222222222222222222222222222222222"}
        """
        try assertVerdict(
            replayed,
            is: ["decision": "rejected", "reason": "leaf_key_mismatch", "reasonCode": 6]
        )

        // `reasonCode` and `expiresAt` are NUMBERS after the crossing and not
        // text. JSON through a C buffer is exactly where a number quietly
        // becomes a string, and the numbers are half of what makes this
        // contract catch a renumbering that left a name alone.
        let accepted = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(try CredentialsFixture.evaluate(caseJSON: good).utf8))
                as? [String: Any]
        )
        XCTAssertEqual(accepted["expiresAt"] as? Int, 1_792_108_800)
        let rejected = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(try CredentialsFixture.evaluate(caseJSON: replayed).utf8)
            ) as? [String: Any]
        )
        XCTAssertEqual(rejected["reasonCode"] as? Int, 6)
    }

    func testACaseThatAddressesNothingRealThrowsRatherThanReturningAVerdict() throws {
        // The distinction the whole replay rests on. A case naming something
        // that no longer exists has to fail loudly — the alternative is a
        // fixture that goes on passing while it tests nothing.
        XCTAssertThrowsError(
            try CredentialsFixture.evaluate(
                caseJSON: """
                {"kind":"credential","call":"validateEverything","nowUnix":0,"trust":[],
                 "token":"pdc1",
                 "leafSeed":"1111111111111111111111111111111111111111111111111111111111111111"}
                """
            )
        ) { error in
            let message = String(describing: error)
            XCTAssertTrue(message.contains("validateEverything"), message)
            // And it lists what IS known, so repointing a case is a read rather
            // than a search.
            XCTAssertTrue(message.contains("validateCredential"), message)
        }

        XCTAssertThrowsError(
            try CredentialsFixture.evaluate(caseJSON: #"{"kind":"teleport"}"#)
        ) { error in
            XCTAssertTrue(String(describing: error).contains("teleport"), String(describing: error))
        }

        // A seed of the wrong length is the case-author mistake most likely to
        // pass for a verdict if it were tolerated: a truncated hex string would
        // silently become a different key, and therefore a different `kid`.
        XCTAssertThrowsError(
            try CredentialsFixture.evaluate(
                caseJSON: #"{"kind":"credential","call":"validateToken","nowUnix":0,"trust":["07"]}"#
            )
        ) { error in
            XCTAssertTrue(
                String(describing: error).contains("64 hex characters"), String(describing: error)
            )
        }
    }

    func testACaseWithNoKindIsStillARulesCase() throws {
        // The dispatch defaults the way `mls/fixtures/rules.json` needs it to,
        // and this is the assertion that catches it defaulting the other way —
        // which would leave both fixtures green here and red in a client built
        // from an older commit.
        try assertVerdict(
            #"{"call":"evaluate","proposal":{"kind":"add","sender":"member"}}"#,
            is: ["decision": "allow"]
        )
    }

    private func assertVerdict(
        _ caseJSON: String,
        is expected: [String: Any],
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let text = try CredentialsFixture.evaluate(caseJSON: caseJSON)
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
