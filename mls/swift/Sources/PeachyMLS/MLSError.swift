// SPDX-License-Identifier: MIT
import Foundation
import PeachyMLSCore

/// A failure from the MLS core, with the code the C ABI returned and the
/// sentence it left behind.
///
/// Both halves matter. The code is what a caller branches on — "this device
/// was removed" is a different situation from "that did not decode" — and the
/// message is what a bug report needs, because a code alone cannot say WHICH
/// of a credential's eight checks failed.
public struct MLSError: Error, Hashable, CustomStringConvertible, LocalizedError {
    /// The status the entry point returned.
    public let code: Code
    /// `peachy_mls_last_error()`, copied out before any other call could
    /// overwrite it. Never empty in practice: every failure path in the ABI
    /// sets one.
    public let message: String

    public init(code: Code, message: String) {
        self.code = code
        self.message = message
    }

    public var description: String { "\(code): \(message)" }
    public var errorDescription: String? { description }

    /// A call made after ``MLSClient/close()``. Swift's own, never the
    /// library's: the point of the check is that the call does not reach it.
    public static let closed = MLSError(
        code: .closed,
        message: "this MLSClient has been closed"
    )

    /// The status codes from `peachy_mls.h`, plus a case for a number a future
    /// version of the library might return — an `enum` that could not
    /// represent one would have to trap, crash or lie.
    public enum Code: Hashable, Sendable, CustomStringConvertible {
        case nullArgument
        case credentialRejected
        case policyRefused
        case mls
        case codec
        case noSuchGroup
        case notAMember
        case noSuchMember
        case unsupported
        case invalidArgument
        /// A panic caught at the C boundary. Always a bug in the library or one
        /// of its dependencies; never something a caller did. What the call
        /// wrote is rolled back and the ``MLSClient`` is closed (every later
        /// call throws ``MLSError/closed``): open a new one over the same store.
        case panic
        /// This device's MLS store could not be read or written — an
        /// unopenable path, a full disk, a database another process has locked.
        /// The state is intact or it is not there; it is never half written.
        case storage
        /// A Welcome into a group this device is already in — a replay, or one
        /// from a commit the delivery service refused. The live group is
        /// untouched; the one-time key package the Welcome named is spent.
        case alreadyAMember
        /// A group-context change (a rename) could not be made because some
        /// member's leaf does not advertise the extension it sets. The remedy
        /// is person-sized — that member runs a current build, whose next leaf
        /// renewal (before its next send into the group, or as its app starts
        /// or comes to the foreground) carries the capability — which is why
        /// it is its own code rather than an unreadable protocol failure.
        case extensionUnsupported
        /// A group message handed to the door that does not take its kind
        /// (`MLSClient.processMessage` / `processCommit`): refused before the
        /// engine read it, so nothing moved. Not a message that failed to open
        /// and not a commit that strands — drop it and log it.
        case wrongDoor
        /// A message that opened and verified, from a device the group has
        /// since removed (sealed at an earlier epoch by a leaf no longer in the
        /// tree). Drop it in silence: no placeholder, no resend ask, no head
        /// check.
        case notFromAMember
        /// A Welcome refused for who signed it: a device this account forgot,
        /// into any group; or, into a group this device knew, a signer whose
        /// credential does not identify. Nothing was taken. Drop the Welcome
        /// and log it; a device waiting to rejoin keeps waiting.
        case welcomeFromOutsider
        /// The group holds a saved commit whose verdict this device never
        /// heard (``MLSClient/hasSavedCommit(groupID:)``): forgetting it, or a
        /// Welcome replacing it, would drop a commit the server may have
        /// taken. Nothing changed. Settle it against the group's head
        /// (``MLSClient/settleSavedCommit(groupID:headEpoch:headVerifier:)``)
        /// and try again; never ask to rejoin meanwhile.
        case settleFirst
        /// An application message this device already opened, the very
        /// bytes handed over again. Nothing in it is new: acknowledge it and
        /// drop it in silence — no placeholder, no resend ask, no
        /// notification, no head check.
        case duplicate
        /// A key was handed for a store written in the clear. Nothing was
        /// opened. Encrypt it with ``MLSClient/encryptStoreInPlace(path:key:)``
        /// and open it again; never delete it, which drops the device out
        /// of every group.
        case plaintextStore
        /// The store, or its `-wal`, `-shm` or `-journal`, is writable by
        /// group or others, or is a symbolic link, so another local user
        /// could plant a log the bundled SQLite would read as the store's
        /// own. Nothing was opened, and no retry opens it: make the files
        /// writable only by their owner. A link at the store's own path may
        /// be replaced with the file it names; never adopt the file a
        /// `-wal`, `-shm` or `-journal` link names, and remove such a link
        /// only once the store's owner is known to have made it. Then open
        /// it again. Never delete the store to start over.
        case insecureStore
        /// A message or commit framed at an epoch past this copy's: the copy
        /// is behind or forked and will not catch up from what was
        /// delivered. Nothing moved. Read the group's head and judge it
        /// (`MLSClient.recoveryBegin`, then `recoveryJudge` with
        /// `.sealedAhead`), which says whether to rejoin; never rejoin on
        /// this alone. Show it as a message that will not open.
        ///
        /// From ``MLSClient/sealEnvelope(groupId:kind:inner:)`` it means
        /// something else: the message or commit was made at an epoch this
        /// copy no longer keeps, and nothing was sealed. Encrypt the message
        /// again at the current epoch and seal that; never resend the old
        /// bytes, and do not read or judge the head.
        case staleCopy
        /// Not a C status at all: a call on a client that has been closed. It
        /// carries a negative raw value because every code the ABI returns is
        /// positive, so it can never collide with one.
        case closed
        case other(Int32)

        public init(_ raw: Int32) {
            switch raw {
            case PEACHY_MLS_ERR_NULL_ARGUMENT: self = .nullArgument
            case PEACHY_MLS_ERR_CREDENTIAL: self = .credentialRejected
            case PEACHY_MLS_ERR_POLICY: self = .policyRefused
            case PEACHY_MLS_ERR_MLS: self = .mls
            case PEACHY_MLS_ERR_CODEC: self = .codec
            case PEACHY_MLS_ERR_NO_SUCH_GROUP: self = .noSuchGroup
            case PEACHY_MLS_ERR_NOT_A_MEMBER: self = .notAMember
            case PEACHY_MLS_ERR_NO_SUCH_MEMBER: self = .noSuchMember
            case PEACHY_MLS_ERR_UNSUPPORTED: self = .unsupported
            case PEACHY_MLS_ERR_INVALID_ARGUMENT: self = .invalidArgument
            case PEACHY_MLS_ERR_PANIC: self = .panic
            case PEACHY_MLS_ERR_STORAGE: self = .storage
            case PEACHY_MLS_ERR_ALREADY_A_MEMBER: self = .alreadyAMember
            case PEACHY_MLS_ERR_EXTENSION_UNSUPPORTED: self = .extensionUnsupported
            case PEACHY_MLS_ERR_WRONG_DOOR: self = .wrongDoor
            case PEACHY_MLS_ERR_NOT_FROM_A_MEMBER: self = .notFromAMember
            case PEACHY_MLS_ERR_WELCOME_FROM_OUTSIDER: self = .welcomeFromOutsider
            case PEACHY_MLS_ERR_SETTLE_FIRST: self = .settleFirst
            case PEACHY_MLS_ERR_DUPLICATE: self = .duplicate
            case PEACHY_MLS_ERR_PLAINTEXT_STORE: self = .plaintextStore
            case PEACHY_MLS_ERR_INSECURE_STORE: self = .insecureStore
            case PEACHY_MLS_ERR_STALE_COPY: self = .staleCopy
            default: self = .other(raw)
            }
        }

        public var rawValue: Int32 {
            switch self {
            case .nullArgument: return PEACHY_MLS_ERR_NULL_ARGUMENT
            case .credentialRejected: return PEACHY_MLS_ERR_CREDENTIAL
            case .policyRefused: return PEACHY_MLS_ERR_POLICY
            case .mls: return PEACHY_MLS_ERR_MLS
            case .codec: return PEACHY_MLS_ERR_CODEC
            case .noSuchGroup: return PEACHY_MLS_ERR_NO_SUCH_GROUP
            case .notAMember: return PEACHY_MLS_ERR_NOT_A_MEMBER
            case .noSuchMember: return PEACHY_MLS_ERR_NO_SUCH_MEMBER
            case .unsupported: return PEACHY_MLS_ERR_UNSUPPORTED
            case .invalidArgument: return PEACHY_MLS_ERR_INVALID_ARGUMENT
            case .panic: return PEACHY_MLS_ERR_PANIC
            case .storage: return PEACHY_MLS_ERR_STORAGE
            case .alreadyAMember: return PEACHY_MLS_ERR_ALREADY_A_MEMBER
            case .extensionUnsupported: return PEACHY_MLS_ERR_EXTENSION_UNSUPPORTED
            case .wrongDoor: return PEACHY_MLS_ERR_WRONG_DOOR
            case .notFromAMember: return PEACHY_MLS_ERR_NOT_FROM_A_MEMBER
            case .welcomeFromOutsider: return PEACHY_MLS_ERR_WELCOME_FROM_OUTSIDER
            case .settleFirst: return PEACHY_MLS_ERR_SETTLE_FIRST
            case .duplicate: return PEACHY_MLS_ERR_DUPLICATE
            case .plaintextStore: return PEACHY_MLS_ERR_PLAINTEXT_STORE
            case .insecureStore: return PEACHY_MLS_ERR_INSECURE_STORE
            case .staleCopy: return PEACHY_MLS_ERR_STALE_COPY
            case .closed: return -1
            case let .other(raw): return raw
            }
        }

        public var description: String {
            switch self {
            case .nullArgument: return "nullArgument"
            case .credentialRejected: return "credentialRejected"
            case .policyRefused: return "policyRefused"
            case .mls: return "mls"
            case .codec: return "codec"
            case .noSuchGroup: return "noSuchGroup"
            case .notAMember: return "notAMember"
            case .noSuchMember: return "noSuchMember"
            case .unsupported: return "unsupported"
            case .invalidArgument: return "invalidArgument"
            case .panic: return "panic"
            case .storage: return "storage"
            case .alreadyAMember: return "alreadyAMember"
            case .extensionUnsupported: return "extensionUnsupported"
            case .wrongDoor: return "wrongDoor"
            case .notFromAMember: return "notFromAMember"
            case .welcomeFromOutsider: return "welcomeFromOutsider"
            case .settleFirst: return "settleFirst"
            case .duplicate: return "duplicate"
            case .plaintextStore: return "plaintextStore"
            case .insecureStore: return "insecureStore"
            case .staleCopy: return "staleCopy"
            case .closed: return "closed"
            case let .other(raw): return "unknown(\(raw))"
            }
        }
    }
}

/// The last error message for THIS thread, copied into a Swift `String`.
///
/// The pointer the ABI returns is owned by the library and valid only until
/// that thread's next `peachy_mls_*` call, so the copy is not a nicety: a
/// stored pointer is a use-after-free two calls later.
func lastErrorMessage() -> String {
    guard let pointer = peachy_mls_last_error() else {
        return "the library reported a failure but left no message"
    }
    return String(cString: pointer)
}
