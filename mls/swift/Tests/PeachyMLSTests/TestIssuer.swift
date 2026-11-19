// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import PeachyMLSCore

@testable import PeachyMLS

/// The `pdc1` issuer, reached through the C door that
/// `mls/cabi/src/lib.rs` exposes behind the `test-issuer` cargo feature.
///
/// **Not the server, and not in a shipping build.** The header declares these
/// entry points inside `#if defined(PEACHY_MLS_TEST_ISSUER)` and only this
/// test target defines it (Package.swift), so a stray issuer call in
/// `PeachyMLS` itself would not compile.
///
/// The alternative was minting `pdc1` tokens in Swift with CryptoKit, which
/// would have meant a second implementation of a format whose whole point is
/// that one implementation verifies what one implementation signs
/// (`docs/identity.md` §Format). A test that mints with its own idea of
/// the format and then verifies with its own idea of the format agrees with
/// itself and nothing else.
final class TestIssuer {
    private let handle: OpaquePointer
    /// The body `GET /healthz/device-credential-keys` would return for this
    /// issuer — the shape `MLSClient.init` takes.
    let trustedKeysJSON: String

    enum Failure: Error, CustomStringConvertible {
        case issuer(Int32, String)

        var description: String {
            switch self {
            case let .issuer(code, message): return "test issuer failed (\(code)): \(message)"
            }
        }
    }

    init(seed: UInt8 = 41) throws {
        let seedBytes = [UInt8](repeating: seed, count: 32)
        var created: OpaquePointer?
        let status = peachy_mls_test_issuer_new(seedBytes, 32, &created)
        guard status == PEACHY_MLS_OK, let created else {
            throw Failure.issuer(status, lastErrorMessage())
        }
        handle = created

        var published = PeachyMlsBuffer()
        let keysStatus = peachy_mls_test_issuer_published_keys(created, &published)
        guard keysStatus == PEACHY_MLS_OK else {
            peachy_mls_test_issuer_free(created)
            throw Failure.issuer(keysStatus, lastErrorMessage())
        }
        defer { peachy_mls_buffer_free(&published) }
        if let bytes = published.data, published.len > 0 {
            trustedKeysJSON = String(
                decoding: Data(bytes: bytes, count: Int(published.len)),
                as: UTF8.self
            )
        } else {
            trustedKeysJSON = ""
        }
    }

    deinit {
        peachy_mls_test_issuer_free(handle)
    }

    /// A device seed derived from one byte, so a test can name its devices
    /// "1", "2" and get a different key each time without carrying 32 bytes
    /// around.
    static func deviceSeed(_ tag: UInt8) -> Data {
        var seed = Data(repeating: 0, count: 32)
        seed[0] = tag
        seed[1] = 0xA5
        return seed
    }

    static var now: Int64 { Int64(Date().timeIntervalSince1970) }

    /// The stand-in account key `credential(...)` certifies `actorId`'s
    /// devices under: SHA-256 of "peachy-test-account", a zero byte and the
    /// actor (`test_account_key` in `mls/core/src/issuer.rs`).
    static func testAccountKey(actorId: String) -> Data {
        Data(SHA256.hash(data: Data("peachy-test-account\0\(actorId)".utf8)))
    }

    /// The account identity key a client holding `actorId`'s test account key
    /// names when it opens. A client that names none refuses every certified
    /// credential, its own included.
    static func heldIdentity(actorId: String) throws -> Data {
        try MLSClient.accountIdentityPublicKey(accountKey: testAccountKey(actorId: actorId))
    }

    /// Mint a credential. The device key in it is derived from `deviceSeed` on
    /// the Rust side, so the token and the seed always agree.
    func credential(
        actorId: String,
        deviceId: String,
        deviceSeed: Data,
        issuedAt: Int64 = TestIssuer.now - 3_600,
        expiresAt: Int64 = TestIssuer.now + 30 * 24 * 3_600
    ) throws -> Data {
        var token = PeachyMlsBuffer()
        let status: Int32 = deviceSeed.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return Int32(-1) }
            return actorId.withCString { actor in
                deviceId.withCString { device in
                    peachy_mls_test_issuer_issue(
                        handle,
                        actor,
                        device,
                        base,
                        UInt(deviceSeed.count),
                        issuedAt,
                        expiresAt,
                        &token
                    )
                }
            }
        }
        guard status == PEACHY_MLS_OK else {
            throw Failure.issuer(status, lastErrorMessage())
        }
        defer { peachy_mls_buffer_free(&token) }
        guard let bytes = token.data, token.len > 0 else {
            throw Failure.issuer(status, "the issuer returned an empty credential")
        }
        return Data(bytes: bytes, count: Int(token.len))
    }

    /// A ready client: a credential, its seed, and the trusted keys that
    /// verify it.
    ///
    /// Ephemeral unless `storePath` says otherwise. Most of this suite is about
    /// what the binding does with buffers and errors, and a file on disk would
    /// only make those tests slower and able to leak state into each other.
    func client(
        actorId: String,
        deviceId: String,
        tag: UInt8,
        issuedAt: Int64 = TestIssuer.now - 3_600,
        expiresAt: Int64 = TestIssuer.now + 30 * 24 * 3_600,
        storePath: String? = nil,
        storeKey: Data? = nil,
        storeMustExist: Bool = false
    ) throws -> MLSClient {
        let seed = TestIssuer.deviceSeed(tag)
        let token = try credential(
            actorId: actorId,
            deviceId: deviceId,
            deviceSeed: seed,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
        return try MLSClient(
            credential: token,
            signatureSeed: seed,
            trustedKeysJSON: trustedKeysJSON,
            storePath: storePath,
            storeKey: storeKey,
            ownAccountIdentity: try TestIssuer.heldIdentity(actorId: actorId),
            storeMustExist: storeMustExist
        )
    }
}
