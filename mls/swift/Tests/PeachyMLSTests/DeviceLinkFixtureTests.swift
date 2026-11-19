// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// The golden device-link fixture, replayed through the C door from Swift.
///
/// `mls/fixtures/device-link.json` is the table of what four clients must each
/// compute when a person approves a new device from one they already have: the
/// exact bytes an approving device signs, the signature over them, whether an
/// approval holds, the QR code a new device shows, and the two-digit number
/// both devices show when neither can scan.
/// `mls/core/tests/device_link_fixture.rs` replays it in Rust,
/// `mls/wasm/tests/node/device-link.test.mjs` from JavaScript and
/// the Android binding's `DeviceLinkFixtureTest` (not in this repository) from
/// Kotlin; this is the Apple half. Same file, same door, every binding — the
/// third sibling of `RulesFixtureTests` and `CredentialsFixtureTests`.
///
/// A replay per binding and not one, because the Rust replay proves the DERIVATION and
/// each binding's replay proves that binding's DOOR. What can only go wrong
/// here is the crossing: a statement that lost its trailing NUL because
/// something assumed a C buffer was NUL-terminated, a `valid` that arrived as
/// text, a refusal that reached Swift as an empty string instead of a thrown
/// error, a number whose leading zero was eaten. None of that is visible from
/// Rust, and an iPhone offering different numbers from the one on the laptop
/// beside it is the exact failure this fixture exists to make impossible.
final class DeviceLinkFixtureTests: XCTestCase {
    /// The format version this replay understands — the same equality
    /// `peachy_mls_core::fixture::FORMAT_VERSION` and the other three replays
    /// assert from their own ends.
    private let formatVersion = 1

    /// Every `call` the table has to reach, spelled out in Swift rather than
    /// read from the file: a derivation from the same source cannot notice
    /// that a call stopped being exercised.
    private let calls = [
        "statement", "sign", "verify", "commitment", "number", "approverNumber", "qr", "qrMatches",
        "accountIdentity", "signAccountDevice", "verifyAccountDevice", "keyPackageIdentity",
        "waiterStep", "signCommitment", "verifyCommitment", "approverStep",
        "linkKey", "signLinkKey", "verifyLinkKey", "signDeviceRevocation", "verifyDeviceRevocation",
        "installRevocationTargets",
    ]

    private func cases() throws -> [[String: Any]] {
        let root = try DeviceLinkFixture.load()
        return try XCTUnwrap(root["cases"] as? [[String: Any]], "`cases` is an array of objects")
    }

    private func testCase(_ id: String) throws -> [String: Any] {
        try XCTUnwrap(
            try cases().first { ($0["id"] as? String) == id },
            "the fixture has no case \(id)"
        )
    }

    func testTheFixtureIsTheFormatThisBuildReads() throws {
        let root = try DeviceLinkFixture.load()
        XCTAssertEqual(
            root["version"] as? Int, formatVersion,
            "the fixture's format version and this replay disagree"
        )
        // A floor, deliberately under today's count, so a replay that stopped
        // finding cases cannot read as a clean pass over nothing.
        XCTAssertGreaterThanOrEqual(try cases().count, 34, "the fixture shrank or stopped parsing")

        for testCase in try cases() {
            let id = testCase["id"] ?? "<no id>"
            // Every case says which table it belongs to. An absent `kind`
            // means `rules` at the door, which is what keeps rules.json
            // working unchanged — and what would send a device-link case to
            // the policy layer.
            XCTAssertEqual(
                testCase["kind"] as? String, "device_link",
                "case \(id) has no kind: \"device_link\""
            )
            // Exactly one of the two, never both and never neither: a case
            // with an `expect` AND an `expectError` would be read differently
            // by different replays, and one with neither asserts nothing.
            XCTAssertNotEqual(
                testCase["expect"] == nil, testCase["expectError"] == nil,
                "case \(id) needs exactly one of `expect` and `expectError`"
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

            // The whole case object goes over, `expect`, `expectError` and
            // `why` included and ignored — exactly what the other three
            // replays hand to the same door, so a difference between two
            // clients is a difference in a BINDING and can never be a
            // difference in what was asked.
            if let expectedError = testCase["expectError"] as? String {
                // A refusal is NOT a verdict, and blurring the two is the one
                // thing this replay must not do: a signing key of the wrong
                // length handed to `statement` is a caller mistake, not a
                // `valid: false`.
                do {
                    let answered = try DeviceLinkFixture.evaluate(case: testCase)
                    failures.append(
                        "  \(id)\n    expected a refusal naming \(expectedError)\n"
                            + "    actual   \(answered)"
                    )
                } catch {
                    let message = String(describing: error)
                    if !message.contains(expectedError) {
                        failures.append(
                            "  \(id)\n    expected a refusal naming \(expectedError)\n"
                                + "    actual   \(message)"
                        )
                    }
                }
                continue
            }

            let expected = try XCTUnwrap(
                testCase["expect"] as? [String: Any], "case \(id) has no `expect`"
            )
            do {
                let verdictText = try DeviceLinkFixture.evaluate(case: testCase)
                let verdict = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: Data(verdictText.utf8)) as? [String: Any],
                    "case \(id): a verdict is a JSON object; got \(verdictText)"
                )
                // Whole-object equality, not field by field: an EXTRA key in
                // the verdict is a disagreement too, and it is the kind a
                // per-field check reads straight past.
                if NSDictionary(dictionary: verdict) != NSDictionary(dictionary: expected) {
                    failures.append("  \(id)\n    expected \(expected)\n    actual   \(verdict)")
                }
            } catch {
                failures.append("  \(id)\n    expected \(expected)\n    actual   refused: \(error)")
            }
        }

        XCTAssertTrue(
            failures.isEmpty,
            """
            \(failures.count) of \(all.count) fixture cases disagree with \
            mls/core/src/device_link.rs as the Swift binding reports it.
            Either the derivation changed — in which case every client changed with it and the \
            fixture is the record of that — or the fixture is wrong. Note that a change to \
            either domain string changes every statement, signature and code in this file.
            \(failures.joined(separator: "\n"))
            """
        )
    }

    func testEveryCallIsReachedBySomeCase() throws {
        let all = try cases()
        let reached = Set(all.compactMap { $0["call"] as? String })
        let missing = calls.filter { !reached.contains($0) }
        XCTAssertTrue(
            missing.isEmpty,
            """
            no fixture case calls \(missing.joined(separator: ", ")). A call nothing reaches is a \
            function three clients are not held to, and it can go wrong in one of them with \
            nothing going red.
            """
        )

        for testCase in all {
            let call = testCase["call"] as? String ?? ""
            XCTAssertTrue(
                calls.contains(call), "case \(testCase["id"] ?? "<no id>"): no such call \(call)"
            )
        }

        let refusals = all.filter { $0["expectError"] != nil }.count
        XCTAssertGreaterThanOrEqual(
            refusals, 6,
            """
            only \(refusals) refusal cases — the refusals ARE the contract for three of the four \
            calls, and a table with one of them says nothing about the rest
            """
        )
    }

    func testAVerifyVerdictIsABooleanAfterTheCrossing() throws {
        // JSON through a C buffer is exactly where a boolean quietly becomes
        // text, and `valid` is the one field in this table that a truthy check
        // would read past.
        let holds = try verdict(for: try testCase("verify/round-trip"))
        XCTAssertEqual(holds["valid"] as? Bool, true)
        let doesNot = try verdict(for: try testCase("verify/one-flipped-signature-bit"))
        XCTAssertEqual(doesNot["valid"] as? Bool, false)
    }

    func testTheBindingsOwnEntryPointsAgreeWithTheFixtureDoor() throws {
        // The four functions an Apple client will actually call, checked
        // against the same golden values. They are unconditional in the
        // xcframework, while the fixture door is not, so a replay that only
        // ever went through `evaluateFixtureCase` would leave the product
        // surface compiled and unexercised.
        let statementCase = try testCase("statement/ada-laptop")
        let deviceId = try XCTUnwrap(statementCase["deviceId"] as? String)
        let signingKey = DeviceLinkFixture.bytes(
            try XCTUnwrap(statementCase["signingKeyHex"] as? String)
        )
        XCTAssertEqual(
            DeviceLinkFixture.hex(
                try MLSClient.deviceApprovalStatement(deviceId: deviceId, signingKey: signingKey)
            ),
            (statementCase["expect"] as? [String: Any])?["statementHex"] as? String
        )

        let signCase = try testCase("sign/ada-approves-the-laptop")
        let seed = DeviceLinkFixture.bytes(try XCTUnwrap(signCase["seedHex"] as? String))
        let signedDeviceId = try XCTUnwrap(signCase["deviceId"] as? String)
        let signedKey = DeviceLinkFixture.bytes(
            try XCTUnwrap(signCase["signingKeyHex"] as? String)
        )
        let signature = try MLSClient.signDeviceApproval(
            seed: seed, deviceId: signedDeviceId, signingKey: signedKey
        )
        XCTAssertEqual(signature.count, 64)
        XCTAssertEqual(
            DeviceLinkFixture.hex(signature),
            (signCase["expect"] as? [String: Any])?["signatureHex"] as? String
        )

        let approver = try MLSClient.signingKeyPublicKey(seed: seed)
        XCTAssertTrue(
            MLSClient.verifyDeviceApproval(
                approverKey: approver, deviceId: signedDeviceId, signingKey: signedKey,
                signature: signature
            )
        )

        // The number, at the binding's own door: commit, then compute.
        let numberCase = try testCase("number/ordinary")
        func hex(_ key: String) throws -> Data {
            DeviceLinkFixture.bytes(try XCTUnwrap(numberCase[key] as? String))
        }
        let commitment = try MLSClient.deviceLinkCommitment(approverNonce: try hex("approverNonceHex"))
        XCTAssertEqual(commitment, try hex("commitmentHex"))
        XCTAssertEqual(
            try MLSClient.deviceLinkNumber(
                newDeviceKey: try hex("newDeviceKeyHex"), approverKey: try hex("approverKeyHex"),
                approverCommitment: commitment, deviceNonce: try hex("deviceNonceHex"),
                approverNonce: try hex("approverNonceHex")
            ),
            (numberCase["expect"] as? [String: Any])?["number"] as? String
        )
        // A nonce that does not open the commitment throws, never a number.
        XCTAssertThrowsError(
            try MLSClient.deviceLinkNumber(
                newDeviceKey: try hex("newDeviceKeyHex"), approverKey: try hex("approverKeyHex"),
                approverCommitment: commitment, deviceNonce: try hex("deviceNonceHex"),
                approverNonce: try hex("deviceNonceHex")
            )
        )

        // The approver's number, at its own door too.
        let approverCase = try testCase("approverNumber/ordinary")
        func approverHex(_ key: String) throws -> Data {
            DeviceLinkFixture.bytes(try XCTUnwrap(approverCase[key] as? String))
        }
        XCTAssertEqual(
            try MLSClient.deviceLinkApproverNumber(
                newDeviceKey: try approverHex("newDeviceKeyHex"),
                approverKey: try approverHex("approverKeyHex"),
                approverCommitment: try approverHex("commitmentHex"),
                deviceNonce: try approverHex("deviceNonceHex"),
                approverNonce: try approverHex("approverNonceHex")
            ),
            (approverCase["expect"] as? [String: Any])?["number"] as? String
        )

        // And the QR code, matched only by itself, carrying its secret.
        let qrCase = try testCase("qr/the-new-laptop")
        let qrId = try XCTUnwrap(qrCase["deviceId"] as? String)
        let qrKey = DeviceLinkFixture.bytes(try XCTUnwrap(qrCase["signingKeyHex"] as? String))
        let qrSecret = DeviceLinkFixture.bytes(try XCTUnwrap(qrCase["linkSecretHex"] as? String))
        let qr = try MLSClient.deviceLinkQR(deviceId: qrId, signingKey: qrKey, linkSecret: qrSecret)
        XCTAssertEqual(qr, (qrCase["expect"] as? [String: Any])?["qr"] as? String)
        XCTAssertTrue(MLSClient.deviceLinkQRMatches(scanned: qr, deviceId: qrId, signingKey: qrKey))
        XCTAssertFalse(
            MLSClient.deviceLinkQRMatches(scanned: qr, deviceId: qrId, signingKey: Data(repeating: 0x33, count: 32))
        )
        XCTAssertEqual(MLSClient.deviceLinkQRSecret(scanned: qr, deviceId: qrId, signingKey: qrKey), qrSecret)
        XCTAssertNil(
            MLSClient.deviceLinkQRSecret(scanned: qr, deviceId: qrId, signingKey: Data(repeating: 0x33, count: 32))
        )

        // And the waiting device's rule, every row, at the binding's own door.
        for waiter in try cases() where waiter["call"] as? String == "waiterStep" {
            let id = waiter["id"] as? String ?? "<no id>"
            func bytes(_ key: String) -> Data {
                DeviceLinkFixture.bytes(waiter[key] as? String ?? "")
            }
            let step = {
                try MLSClient.deviceLinkWaiterStep(
                    boundApproverId: waiter["boundApproverDeviceId"] as? String ?? "",
                    boundApproverKey: bytes("boundApproverKeyHex"),
                    boundCommitment: bytes("boundCommitmentHex"),
                    approverId: waiter["approverDeviceId"] as? String ?? "",
                    approverKey: bytes("approverKeyHex"),
                    commitment: bytes("commitmentHex"))
            }
            if let expectedError = waiter["expectError"] as? String {
                XCTAssertThrowsError(try step(), id) { error in
                    XCTAssertTrue(String(describing: error).contains(expectedError), "\(id): \(error)")
                }
            } else {
                XCTAssertEqual(
                    try step().name,
                    (waiter["expect"] as? [String: Any])?["waiterStep"] as? String, id)
            }
        }

        // The approving device's rule, every row: the one that fixes the
        // waiting device's nonce before revealing.
        for row in try cases() where row["call"] as? String == "approverStep" {
            let id = row["id"] as? String ?? "<no id>"
            func bytes(_ key: String) -> Data {
                DeviceLinkFixture.bytes(row[key] as? String ?? "")
            }
            let step = {
                try MLSClient.deviceLinkApproverStep(
                    pendingKey: bytes("pendingKeyHex"),
                    commitment: bytes("commitmentHex"),
                    boundDeviceNonce: bytes("boundDeviceNonceHex"),
                    listedKey: bytes("listedKeyHex"),
                    listedCommitment: bytes("listedCommitmentHex"),
                    listedDeviceNonce: bytes("listedDeviceNonceHex"),
                    listedApproverNonce: bytes("listedApproverNonceHex"))
            }
            if let expectedError = row["expectError"] as? String {
                XCTAssertThrowsError(try step(), id) { error in
                    XCTAssertTrue(String(describing: error).contains(expectedError), "\(id): \(error)")
                }
            } else {
                XCTAssertEqual(
                    try step().name,
                    (row["expect"] as? [String: Any])?["approverStep"] as? String, id)
            }
        }

        // The commitment signature: golden bytes when signing, a plain
        // true/false when verifying.
        for row in try cases() where row["call"] as? String == "signCommitment" {
            let id = row["id"] as? String ?? "<no id>"
            let sign = {
                try MLSClient.signDeviceLinkCommitment(
                    seed: DeviceLinkFixture.bytes(row["seedHex"] as? String ?? ""),
                    pendingDeviceId: row["deviceId"] as? String ?? "",
                    pendingKey: DeviceLinkFixture.bytes(row["signingKeyHex"] as? String ?? ""),
                    commitment: DeviceLinkFixture.bytes(row["commitmentHex"] as? String ?? ""))
            }
            if let expectedError = row["expectError"] as? String {
                XCTAssertThrowsError(try sign(), id) { error in
                    XCTAssertTrue(String(describing: error).contains(expectedError), "\(id): \(error)")
                }
            } else {
                let expected = try XCTUnwrap(
                    (row["expect"] as? [String: Any])?["signatureHex"] as? String, id)
                XCTAssertEqual(try sign(), DeviceLinkFixture.bytes(expected), id)
            }
        }
        for row in try cases() where row["call"] as? String == "verifyCommitment" {
            let id = row["id"] as? String ?? "<no id>"
            func bytes(_ key: String) -> Data {
                DeviceLinkFixture.bytes(row[key] as? String ?? "")
            }
            XCTAssertEqual(
                MLSClient.verifyDeviceLinkCommitment(
                    approverKey: bytes("approverKeyHex"),
                    pendingDeviceId: row["deviceId"] as? String ?? "",
                    pendingKey: bytes("signingKeyHex"),
                    commitment: bytes("commitmentHex"),
                    signature: bytes("signatureHex")),
                (row["expect"] as? [String: Any])?["valid"] as? Bool, id)
        }
    }

    func testVerifyDeviceApprovalReturnsFalseRatherThanThrowing() throws {
        // The asymmetry is the design. A malformed key, a wrong length and a
        // bad signature all mean "this approval does not hold" — a caller able
        // to tell them apart would be holding an oracle. Building a number
        // over one key in both roles, on the other hand, is a caller mistake
        // with no safe answer: it would render as a MATCH on the screen that
        // is asking whether these are two different machines.
        let signCase = try testCase("sign/ada-approves-the-laptop")
        let seed = DeviceLinkFixture.bytes(try XCTUnwrap(signCase["seedHex"] as? String))
        let deviceId = try XCTUnwrap(signCase["deviceId"] as? String)
        let signingKey = DeviceLinkFixture.bytes(
            try XCTUnwrap(signCase["signingKeyHex"] as? String)
        )
        let signature = try MLSClient.signDeviceApproval(
            seed: seed, deviceId: deviceId, signingKey: signingKey
        )
        let approver = try MLSClient.signingKeyPublicKey(seed: seed)

        XCTAssertFalse(
            MLSClient.verifyDeviceApproval(
                approverKey: Data(), deviceId: deviceId, signingKey: signingKey,
                signature: signature
            )
        )
        XCTAssertFalse(
            MLSClient.verifyDeviceApproval(
                approverKey: approver, deviceId: deviceId, signingKey: signingKey,
                signature: signature.dropLast()
            )
        )
        XCTAssertFalse(
            MLSClient.verifyDeviceApproval(
                approverKey: approver, deviceId: "", signingKey: signingKey, signature: signature
            )
        )

        let key = Data(repeating: 0xAA, count: 32)
        let nonce = Data(repeating: 0x66, count: 32)
        XCTAssertThrowsError(
            try MLSClient.deviceLinkNumber(
                newDeviceKey: key, approverKey: key,
                approverCommitment: try MLSClient.deviceLinkCommitment(approverNonce: nonce),
                deviceNonce: nonce, approverNonce: nonce
            )
        ) { error in
            XCTAssertTrue(
                String(describing: error).contains("itself"), String(describing: error)
            )
        }
        XCTAssertThrowsError(
            try MLSClient.deviceApprovalStatement(
                deviceId: "device-ada-laptop", signingKey: key.dropLast()
            )
        ) { error in
            XCTAssertTrue(
                String(describing: error).contains("32 bytes"), String(describing: error)
            )
        }
        XCTAssertThrowsError(
            try MLSClient.deviceApprovalStatement(deviceId: "", signingKey: key)
        ) { error in
            XCTAssertTrue(
                String(describing: error).contains("must not be empty"), String(describing: error)
            )
        }
    }

    func testAKeyPackagesIdentityComesOutOfItsOwnBytes() throws {
        // The fifth call, through the binding's OWN door rather than the
        // fixture's. A real client produces a key package, a different client
        // reads it, and the signing key that comes back is the one the producer
        // actually holds — which is what lets an adder check a device approval
        // without taking the server's word for which key it is checking.
        let issuer = try TestIssuer(seed: 7)
        let producing = try issuer.client(
            actorId: "actor-ada", deviceId: "device-ada-laptop", tag: 0x33
        )
        let reading = try issuer.client(
            actorId: "actor-bo", deviceId: "device-bo-phone", tag: 0x44
        )
        let keyPackage = try producing.generateKeyPackage().data

        let read = try reading.keyPackageIdentity(keyPackage)
        let identity = try XCTUnwrap(read.verified, "the credential verifies")
        XCTAssertEqual(identity.actorId, "actor-ada")
        XCTAssertEqual(identity.deviceId, "device-ada-laptop")
        // THE assertion. The key handed to `verifyDeviceApproval` is the
        // producer's own, taken out of the package, and nobody in between got
        // to name it.
        XCTAssertEqual(read.deviceKey.count, 32)
        XCTAssertEqual(
            read.deviceKey,
            try MLSClient.signingKeyPublicKey(seed: TestIssuer.deviceSeed(0x33))
        )

        // And an approval over that key, checked the way an adder would.
        let approverSeed = Data(repeating: 0x11, count: 32)
        let approval = try MLSClient.signDeviceApproval(
            seed: approverSeed, deviceId: identity.deviceId, signingKey: read.deviceKey
        )
        let approver = try MLSClient.signingKeyPublicKey(seed: approverSeed)
        XCTAssertTrue(
            MLSClient.verifyDeviceApproval(
                approverKey: approver, deviceId: identity.deviceId,
                signingKey: read.deviceKey, signature: approval
            )
        )
        // The same approval against the key a lying directory might have named
        // instead does NOT hold, which is the whole reason the key is read
        // here rather than taken from the response that carried the package.
        XCTAssertFalse(
            MLSClient.verifyDeviceApproval(
                approverKey: approver, deviceId: identity.deviceId,
                signingKey: try MLSClient.signingKeyPublicKey(
                    seed: TestIssuer.deviceSeed(0x55)
                ),
                signature: approval
            )
        )

        // Bytes that are not a key package THROW — a refusal, not a rejection.
        // A caller must not be able to report "that device's credential is bad"
        // about something that was never a credential.
        XCTAssertThrowsError(try reading.keyPackageIdentity(Data([0xDE, 0xAD, 0xBE, 0xEF])))
        XCTAssertThrowsError(try reading.keyPackageIdentity(Data()))
    }

    func testACaseThatAddressesNothingRealThrowsRatherThanReturningAVerdict() throws {
        // The distinction the whole replay rests on. A case naming something
        // that no longer exists has to fail loudly — the alternative is a
        // fixture that goes on passing while it tests nothing.
        XCTAssertThrowsError(
            try DeviceLinkFixture.evaluate(
                caseJSON: """
                {"kind":"device_link","call":"compareEverything","deviceId":"device-ada-laptop",
                 "signingKeyHex":"22"}
                """
            )
        ) { error in
            let message = String(describing: error)
            XCTAssertTrue(message.contains("compareEverything"), message)
            // And it lists what IS known, so repointing a case is a read
            // rather than a search.
            XCTAssertTrue(message.contains("statement, sign, verify, commitment, number"), message)
        }

        XCTAssertThrowsError(
            try DeviceLinkFixture.evaluate(caseJSON: #"{"kind":"teleport"}"#)
        ) { error in
            XCTAssertTrue(String(describing: error).contains("teleport"), String(describing: error))
        }

        // A missing field names what is missing rather than defaulting to
        // something that would quietly hash the wrong thing.
        XCTAssertThrowsError(
            try DeviceLinkFixture.evaluate(caseJSON: #"{"kind":"device_link","call":"number"}"#)
        ) { error in
            XCTAssertTrue(String(describing: error).contains("newDeviceKeyHex"), String(describing: error))
        }

        // Hex that is not hex is a case-author mistake and not an input: a
        // truncated string would silently become different bytes.
        XCTAssertThrowsError(
            try DeviceLinkFixture.evaluate(
                caseJSON: #"{"kind":"device_link","call":"commitment","approverNonceHex":"zz"}"#
            )
        ) { error in
            XCTAssertTrue(String(describing: error).contains("is not hex"), String(describing: error))
        }
    }

    func testACaseWithNoKindIsStillARulesCase() throws {
        // `rules.json` carries no `kind` and must go on meaning the policy
        // table. This is the assertion that would catch the new arm swallowing
        // it — which would leave all three fixtures green here and red in a
        // client built from an older commit.
        let text = try DeviceLinkFixture.evaluate(
            caseJSON: #"{"call":"evaluate","proposal":{"kind":"add","sender":"member"}}"#
        )
        let actual = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any]
        )
        XCTAssertEqual(NSDictionary(dictionary: actual), NSDictionary(dictionary: ["decision": "allow"]))
    }

    private func verdict(
        for testCase: [String: Any], file: StaticString = #filePath, line: UInt = #line
    ) throws -> [String: Any] {
        let text = try DeviceLinkFixture.evaluate(case: testCase)
        return try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
            "a verdict is a JSON object; got \(text)",
            file: file, line: line
        )
    }
}
