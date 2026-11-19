// SPDX-License-Identifier: MIT
import Foundation
import PeachyMLSCore

/// Who a leaf belongs to: the KEY layer of `docs/identity.md`, never a
/// label a person reads.
///
/// `actorId` is `users.actor_id` and `deviceId` is the device that holds the
/// leaf's signature key.
///
/// The raw key itself sits on the thing that CARRIES an identity rather than
/// on the identity — `RosterEntry.deviceKey` for a leaf in a group,
/// `KeyPackageIdentity.deviceKey` for a key package — because that is where a
/// caller needs it: to check a device approval, against a device this person
/// already has. By the time an `Identity` exists the core has verified that
/// the credential binds that key (`docs/mls-core.md` §The leaf credential is a
/// Peachy device credential, rule 5), so the key is a fact the identity has
/// already been proved against; a caller reads it to ask a SECOND question,
/// not to re-ask the first.
public struct Identity: Hashable, Sendable, CustomStringConvertible {
    public let actorId: String
    public let deviceId: String

    public init(actorId: String, deviceId: String) {
        self.actorId = actorId
        self.deviceId = deviceId
    }

    public var description: String { "\(actorId)/\(deviceId)" }
}

/// A single-use key package: the bytes somebody else needs in order to add
/// this device to a group. Opaque on purpose — nothing in Swift should be
/// reading inside one.
public struct KeyPackage: Hashable, Sendable {
    public let data: Data

    public init(data: Data) {
        self.data = data
    }
}

/// A key package as a DIRECTORY publishes it: the bytes, the RFC 9420
/// reference that names them, and the ciphersuite they are for.
///
/// The three travel together because `PublishKeyPackages` wants all three, and
/// because the reference is the one value a caller must not compute itself:
/// it hashes the bare KeyPackage, not the `MlsMessage` wrapper in
/// ``keyPackage``, so hashing the published bytes gives a plausible answer
/// that no other MLS implementation agrees with.
public struct PublishedKeyPackage: Hashable, Sendable {
    public let keyPackage: KeyPackage
    /// The idempotency key the directory stores this package under.
    public let keyPackageRef: Data
    public let ciphersuite: UInt16

    public init(keyPackage: KeyPackage, keyPackageRef: Data, ciphersuite: UInt16) {
        self.keyPackage = keyPackage
        self.keyPackageRef = keyPackageRef
        self.ciphersuite = ciphersuite
    }
}

/// The result of a change to a group: a commit for every existing member, and
/// a Welcome for whoever was just added.
///
/// `epoch` is the group's epoch after the change, read back from the client —
/// the C ABI returns the buffers and the epoch separately, and joining them
/// here means a caller cannot send a commit while reporting the epoch it
/// superseded.
public struct CommitBundle: Hashable, Sendable {
    public let commit: Data
    /// `nil` unless the change added somebody. An add always produces one.
    public let welcome: Data?
    public let epoch: UInt64

    public init(commit: Data, welcome: Data?, epoch: UInt64) {
        self.commit = commit
        self.welcome = welcome
        self.epoch = epoch
    }
}

/// What `MLSClient.processMessage` or `MLSClient.processCommit` found.
///
/// The shapes mirror `PeachyMlsIncoming` in `peachy_mls.h` exactly, and one
/// absence is worth naming: a `commit` does NOT carry who was added or
/// removed. The C ABI refuses to marshal a variable-length list of identities
/// ("a variable-length list of identities across this boundary is three
/// ownership rules for something a caller can ask for directly"), so the
/// answer is `roster(groupID:)` after the commit has been processed — by which
/// time it is already the new roster, because a commit is merged before
/// `processCommit` returns.
/// How a receiver that cannot open a message should treat the loss
/// (docs/sealed-messages.md §Content hints), carried in the message's
/// authenticated data. Values pinned by `peachy_mls_core::hint`.
public enum ContentHint: UInt8, Hashable, Sendable, CaseIterable {
    /// Show the loss at once; ask for nothing.
    case `default` = 0
    /// Hide the loss, ask for the message again, show it if no answer comes.
    case resendable = 1
    /// Count the loss and show nothing.
    case implicit = 2
    /// `resendable`, for a lane frame a person sent: a reaction, a delete or
    /// an edit. Only a lane-frame answer fills its place.
    case resendableLane = 3

    /// The send's `urgent` bit, the one thing the server learns about what
    /// an envelope carries: a message, reaction, edit or delete
    /// (`peachy_mls_core::hint::hint_is_urgent`).
    public var isUrgent: Bool { self == .resendable || self == .resendableLane }
}

public enum Incoming: Hashable, Sendable {
    /// A message somebody sent to the group.
    case application(Data, sender: Identity, epoch: UInt64)
    /// A proposal that is now queued, waiting for a commit to carry it.
    /// `kind` is a `ProposalKind` code from the core's pinned table.
    case proposalQueued(sender: Identity, kind: UInt32, epoch: UInt64)
    /// A commit, already merged. `removedSelf` means this device was the one
    /// removed, and the group is inactive from here on. `left` names the
    /// people (actor ids, sorted) who LEFT in it: each proposed the removal of
    /// their own leaves (``MLSClient/proposeLeave(groupID:leafIndex:)``) and
    /// the commit removed every one. Empty when nobody left.
    case commit(epoch: UInt64, sender: Identity, removedSelf: Bool, left: [String])
    /// A message this device sent, handed back by the delivery service. The
    /// own sender ratchet is encryption-only, so there is nothing to read.
    case echo(epoch: UInt64)

    /// The group's epoch after this message was processed.
    public var epoch: UInt64 {
        switch self {
        case let .application(_, _, epoch): return epoch
        case let .proposalQueued(_, _, epoch): return epoch
        case let .commit(epoch, _, _, _): return epoch
        case let .echo(epoch): return epoch
        }
    }

    /// The sender, where there is one. `nil` for `.echo`.
    public var sender: Identity? {
        switch self {
        case let .application(_, sender, _): return sender
        case let .proposalQueued(sender, _, _): return sender
        case let .commit(_, sender, _, _): return sender
        case .echo: return nil
        }
    }

}

/// Why a leaf's device credential does not verify. The numbers are pinned in
/// `mls/core/src/error.rs`, and `mls/fixtures/credentials.json` holds every
/// client to the same code on the same input; they are repeated here rather
/// than derived, so a renumbering is a visible diff in both files. A code
/// missing here is not a compile error anywhere — the readers fall back to
/// `.malformed` — which is how 10 read as "did not parse" until
/// `CredentialRejectionTests` pinned the whole table. 9 is retired and not
/// reused.
public enum CredentialRejection: UInt32, CaseIterable, Error, Sendable, CustomStringConvertible {
    case malformed = 1
    case unknownKid = 2
    case badSignature = 3
    case expired = 4
    case notYetValid = 5
    case leafKeyMismatch = 6
    case unsupportedVersion = 7
    case wrongCredentialType = 8
    case implausibleLifetime = 10
    /// The credential's account identity key did not sign its device key.
    case accountSignature = 11
    /// No device of the account has let this one in: no account certificate.
    /// Refused wherever a PEER's leaf is believed.
    case notApproved = 12
    /// This device's own credential is certified under an account identity
    /// key other than the one it derives from the account key it holds.
    case notOwnAccountKey = 13

    public var description: String {
        switch self {
        case .malformed: return "the credential did not parse"
        case .unknownKid: return "the credential names a server key we do not trust"
        case .badSignature: return "the credential's signature does not verify"
        case .expired: return "the credential has expired"
        case .notYetValid: return "the credential is not valid yet"
        case .leafKeyMismatch: return "the leaf's key is not the credential's device key"
        case .unsupportedVersion: return "the credential is a version this build does not know"
        case .wrongCredentialType: return "the leaf does not carry a Peachy device credential"
        case .implausibleLifetime: return "the credential claims a lifetime no issuer gives"
        case .accountSignature: return "the account's signature over the device does not verify"
        case .notApproved: return "no device of the account has let this device in"
        case .notOwnAccountKey: return "the credential is certified under an account key this device does not hold"
        }
    }
}

/// What ``MLSClient/verifyJoinRequest(groupID:actorId:deviceId:proof:keyPackage:pendingActors:)``
/// decided about a signed request to be seated. The raw values are
/// `peachy_mls.h`'s `PEACHY_MLS_JOIN_REQUEST_*` and
/// `mls/fixtures/join-request.json`'s `verdictCode`. Only ``accepted`` may
/// seat anybody.
public enum JoinRequestVerdict: UInt32, Sendable, CaseIterable {
    case accepted = 0
    case malformed = 1
    case credentialRejected = 2
    case identityMismatch = 3
    case badSignature = 4
    case stale = 5
    case fromTheFuture = 6
    /// Holds in every other way, from a person who holds no leaf in this
    /// device's copy of the group, is not this device's own person, and is
    /// not among the people the caller is still adding. Judged last.
    case notAMember = 7

    /// The name the fixture writes.
    public var name: String {
        switch self {
        case .accepted: return "accepted"
        case .malformed: return "malformed"
        case .credentialRejected: return "credential_rejected"
        case .identityMismatch: return "identity_mismatch"
        case .badSignature: return "bad_signature"
        case .stale: return "stale"
        case .fromTheFuture: return "from_the_future"
        case .notAMember: return "not_a_member"
        }
    }
}

/// What ``MLSClient/checkOwnDeviceApproval(keyPackage:approverDeviceId:approvalSignature:)``
/// decided about seating a device of this device's OWN account. The raw values
/// are `peachy_mls.h`'s `PEACHY_MLS_OWN_DEVICE_*`. Only ``known`` and
/// ``approved`` may seat it (``seats``).
public enum OwnDeviceVerdict: UInt32, Sendable, CaseIterable {
    /// On this device's approval chain (or this device itself).
    case known = 0
    /// The approval verifies under a device on this device's approval chain.
    case approved = 1
    /// No device on this device's approval chain made the approval yet:
    /// worth asking again once the chain grows (another sibling may seat it).
    case unanchored = 2
    /// The approval does not verify under the approver it names.
    case badApproval = 3
    /// The package is not a device of this device's own account.
    case notOwnDevice = 4
    /// The package's credential does not verify.
    case credentialRejected = 5

    /// Whether the device may be seated.
    public var seats: Bool { self == .known || self == .approved }

    /// The core's name for the verdict, as logs and the other clients write it.
    public var name: String {
        switch self {
        case .known: return "known"
        case .approved: return "approved"
        case .unanchored: return "unanchored"
        case .badApproval: return "bad_approval"
        case .notOwnDevice: return "not_own_device"
        case .credentialRejected: return "credential_rejected"
        }
    }
}

/// What ``MLSClient/ownDeviceStanding(actorId:deviceId:deviceKey:)`` makes of
/// a leaf (`peachy_mls_core::OwnDeviceStanding`). Only ``thisDevice`` and
/// ``onChain`` count as the person's own device.
public enum OwnDeviceStanding: UInt32, Sendable, CaseIterable {
    /// Another person's device.
    case notOwn = 0
    /// This very device: its id under its own key.
    case thisDevice = 1
    /// A device of this account on this client's approval chain (its own, or
    /// the one it adopted from the main client).
    case onChain = 2
    /// A device of this account on no chain here, or wearing this device's
    /// id or key.
    case offChain = 3
    /// A device this account forgot as removed.
    case forgotten = 4

    /// Whether the device counts as one of the person's own.
    public var countsAsOwn: Bool { self == .thisDevice || self == .onChain }

    /// The core's name for the standing, as logs and the other clients write it.
    public var name: String {
        switch self {
        case .notOwn: return "not_own"
        case .thisDevice: return "this_device"
        case .onChain: return "on_chain"
        case .offChain: return "off_chain"
        case .forgotten: return "forgotten"
        }
    }
}

/// What one Welcome that restored or replaced a group this device knew
/// brought with it (``MLSClient/takeRejoinReport(groupID:)``).
public struct RejoinReport: Sendable, Equatable {
    /// The actor whose commit re-seated this device. Empty in a report of a
    /// contested copy alone (``contested``).
    public let readdedBy: String
    /// The device of ``readdedBy`` that made that commit; empty when unknown
    /// (a stored report that names none).
    public let readdedByDevice: String
    /// Actors the new tree holds whom the roster this device last saw there
    /// did not: people added while it was away.
    public let added: [String]
    /// Whether the Welcome's signer was a device of this person's own that
    /// this device does not trust as one of theirs. Anybody else is drawn by
    /// name.
    public let readdedByUntrusted: Bool
    /// Actors of the roster this device last saw there whom the new tree
    /// leaves out: people gone while it was away. Always drawn.
    public let departed: [String]
    /// Whether the group's admins changed.
    public let adminsChanged: Bool
    /// Whether a head contradicted this device's copy before any head
    /// matched it: the server's word on the group disagrees with the copy.
    public let contested: Bool
    /// The devices, as (actor, device id), of people the new tree keeps that
    /// it leaves out; never this device nor one this account forgot. Logged,
    /// never drawn: the client re-seats its own person's at once.
    public let droppedDevices: [DroppedDevice]
    /// What ``MLSClient/dropRejoinReport(groupID:id:)`` drops it by; 0 from
    /// ``MLSClient/takeRejoinReport(groupID:)`` on a stored report with no
    /// id.
    public let id: UInt64
    /// When to draw it, in Unix milliseconds: the `nowMs` of the first
    /// ``MLSClient/peekRejoinReport(groupID:nowMs:)`` of it, the same on
    /// every later peek; 0 when never peeked.
    public let drawnAtMs: UInt64

    public init(
        readdedBy: String, readdedByDevice: String = "", added: [String],
        readdedByUntrusted: Bool = false, departed: [String] = [],
        adminsChanged: Bool = false, contested: Bool = false,
        droppedDevices: [DroppedDevice] = [], id: UInt64 = 0, drawnAtMs: UInt64 = 0
    ) {
        self.readdedBy = readdedBy
        self.readdedByDevice = readdedByDevice
        self.added = added
        self.readdedByUntrusted = readdedByUntrusted
        self.departed = departed
        self.adminsChanged = adminsChanged
        self.contested = contested
        self.droppedDevices = droppedDevices
        self.id = id
        self.drawnAtMs = drawnAtMs
    }

    /// One of ``droppedDevices``.
    public struct DroppedDevice: Sendable, Equatable {
        public let actorId: String
        public let deviceId: String

        public init(actorId: String, deviceId: String) {
            self.actorId = actorId
            self.deviceId = deviceId
        }
    }
}

/// What a waiting device does with one exchange of the two-digit number,
/// given what its pairing already answered
/// (``MLSClient/deviceLinkWaiterStep(boundApproverId:boundApproverKey:boundCommitment:approverId:approverKey:commitment:)``).
/// The raw values are `peachy_mls.h`'s `PEACHY_MLS_LINK_*`; the names are
/// `mls/fixtures/device-link.json`'s `waiterStep`.
public enum DeviceLinkWaiterStep: UInt32, Sendable, CaseIterable {
    /// Nothing answered yet: answer this commitment, which binds the pairing.
    case answer = 0
    /// The bound exchange: the same nonce again, the number once revealed.
    case `continue` = 1
    /// Another approver's exchange: never answered.
    case ignore = 2
    /// The bound approver restarted or changed key: the pairing is over.
    case interrupted = 3

    /// The name the fixture writes.
    public var name: String {
        switch self {
        case .answer: return "answer"
        case .continue: return "continue"
        case .ignore: return "ignore"
        case .interrupted: return "interrupted"
        }
    }
}

/// What an approving device does next with its exchange for one waiting
/// device
/// (``MLSClient/deviceLinkApproverStep(pendingKey:commitment:boundDeviceNonce:listedKey:listedCommitment:listedDeviceNonce:listedApproverNonce:)``).
/// The raw values are `peachy_mls.h`'s `PEACHY_MLS_APPROVER_*`; the names are
/// `mls/fixtures/device-link.json`'s `approverStep`.
public enum DeviceLinkApproverStep: UInt32, Sendable, CaseIterable {
    /// Our commitment is not on the row and nothing is fixed: post the same one again.
    case commit = 0
    /// Our commitment is on the row; the waiting device has not answered.
    case wait = 1
    /// Reveal. With nothing fixed yet, fix the listed device nonce FIRST.
    case reveal = 2
    /// Our reveal is on the row over the fixed nonce: show the number.
    case show = 3
    /// Something fixed changed: no number, approval closed for this device.
    case interrupted = 4

    /// The name the fixture writes.
    public var name: String {
        switch self {
        case .commit: return "commit"
        case .wait: return "wait"
        case .reveal: return "reveal"
        case .show: return "show"
        case .interrupted: return "interrupted"
        }
    }
}

/// What ``MLSClient/keyPackageIdentity(_:)`` read out of a raw key package.
///
/// `identity` is a `Result` for the same reason a roster entry's is: a key
/// package whose credential has expired is a refusal the caller has to be able
/// to EXPLAIN — "this device's credential expired on the 4th" is a sentence a
/// person can act on, and a thrown error that only says "no" is not.
///
/// ``deviceKey`` is the leaf's own Ed25519 signature key, taken out of the key
/// package's bytes rather than from the directory response: a server could
/// answer with a truthful `(deviceId, signingKey)` pair and a key package
/// carrying a different key. Seating a device of this device's OWN account
/// does not go through this type: the core reads the package itself and checks
/// the device's approval against keys this device already trusts
/// (``MLSClient/checkOwnDeviceApproval(keyPackage:approverDeviceId:approvalSignature:)``,
/// docs/identity.md §What the adder checks).
public struct KeyPackageIdentity: Sendable {
    /// `.success` when the key package's Peachy credential verifies.
    public let identity: Result<Identity, CredentialRejection>
    /// The leaf's raw Ed25519 signature key, which is also the `device_key`
    /// the credential binds. Empty when `identity` is a `.failure`: there is
    /// no key worth handing on from a credential that did not check out.
    public let deviceKey: Data

    public init(identity: Result<Identity, CredentialRejection>, deviceKey: Data) {
        self.identity = identity
        self.deviceKey = deviceKey
    }

    /// The identity if the credential verifies, `nil` otherwise.
    public var verified: Identity? { try? identity.get() }
}

/// One leaf of a group's roster.
///
/// `identity` is a `Result` rather than an optional because a member whose
/// credential has expired is still a member: they are still in the tree and
/// still receive every message, so a roster that dropped them would show a
/// group that does not match who can read it.
public struct RosterEntry: Sendable {
    public let leafIndex: UInt32
    public let identity: Result<Identity, CredentialRejection>
    /// The leaf's raw 32-byte Ed25519 signature key — empty when `identity` is
    /// a `.failure`, since a key from a credential that did not check out is a
    /// key nothing vouched for.
    ///
    /// It comes from the tree, never the directory, because a key taken from
    /// the directory is a key the directory got to choose. The core's own
    /// check before seating a device of this device's own account
    /// (``MLSClient/checkOwnDeviceApproval(keyPackage:approverDeviceId:approvalSignature:)``)
    /// trusts the leaves of this account it sees in its groups the same way.
    public let deviceKey: Data
    /// The leaf's ACCOUNT identity key: the 32-byte Ed25519 key its credential
    /// names and the core verified signs `deviceKey`. Empty for a leaf that
    /// did not verify. The security code is computed from it
    /// (`docs/identity.md` §The security code), and it comes from the
    /// tree for the same reason `deviceKey` does.
    public let accountKey: Data
    /// The leaf's tree signature key, for EVERY leaf, verified or not: what
    /// ``MLSClient/removeMember(groupID:leafIndex:leafKey:)`` takes beside
    /// the index, so a removal names the leaf this entry described and not
    /// whoever sits at its index by the time it runs. Not a key to verify
    /// anything against; that is `deviceKey`.
    public let leafKey: Data
    public init(
        leafIndex: UInt32,
        identity: Result<Identity, CredentialRejection>,
        deviceKey: Data = Data(),
        accountKey: Data = Data(),
        leafKey: Data = Data()
    ) {
        self.leafIndex = leafIndex
        self.identity = identity
        self.deviceKey = deviceKey
        self.accountKey = accountKey
        self.leafKey = leafKey
    }

    /// The identity if the leaf's credential verifies, `nil` otherwise.
    public var verified: Identity? { try? identity.get() }
}


/// The kinds an envelope carries (`mls/core/src/envelope.rs`). The byte
/// crosses the ABI as-is; these name it.
public enum EnvelopeKind {
    /// An MLS application message or proposal.
    public static let message: UInt8 = 1
    /// A commit accepted by the arbiter.
    public static let commit: UInt8 = 2
    /// A device with no leaf asking to be seated: the inner bytes are the
    /// client's JSON `{"d":<device id>,"a":<actor id>}`.
    public static let seatAsk: UInt8 = 3
    /// A typing frame (docs/sealed-messages.md §Typing inside the group).
    public static let typing: UInt8 = 4
    /// A group link's preview (docs/sealed-messages.md §The preview): sealed under
    /// the group id, read with ``MLSClient/openEnvelope(for:_:)``.
    public static let linkPreview: UInt8 = 5
    /// A call signal (docs/calls.md §Signaling): open the inner bytes
    /// with ``MLSClient/openCallSignal(groupID:inner:)``.
    public static let call: UInt8 = 6
}

/// The kind the delivery service puts on a mailbox entry that carries a
/// sealed envelope (`MailboxKind` in docs/delivery.md), as
/// ``MLSClient/processMailboxEntry(groupID:mailboxKind:envelopeKind:inner:receivedAt:)``
/// takes it.
public enum MailboxKind {
    /// `MAILBOX_KIND_MLS`: an envelope of anything but a commit.
    public static let mls = UInt32(PEACHY_MLS_MAILBOX_KIND_MLS)
    /// `MAILBOX_KIND_COMMIT`: a commit the arbiter ordered.
    public static let commit = UInt32(PEACHY_MLS_MAILBOX_KIND_COMMIT)
}

/// Which path an opened mailbox entry takes
/// (``MLSClient/envelopeDoor(mailboxKind:envelopeKind:)``).
public enum EnvelopeDoor: UInt32, Hashable, Sendable, CaseIterable {
    /// Acknowledged unread.
    case drop = 0
    /// The message door.
    case message = 1
    /// The commit door.
    case commit = 2
    /// A seat ask.
    case seatAsk = 3
    /// Call signaling.
    case call = 4
}

/// An envelope ``MLSClient/openEnvelope(_:)`` opened: which of this device's
/// groups it was for, its ``EnvelopeKind``, and the bytes inside.
public struct OpenedEnvelope: Hashable, Sendable {
    public let groupId: Data
    public let kind: UInt8
    public let inner: Data

    public init(groupId: Data, kind: UInt8, inner: Data) {
        self.groupId = groupId
        self.kind = kind
        self.inner = inner
    }
}

/// What ``MLSClient/holdEnvelope(mailboxKind:id:receivedAtMs:envelope:deviceSeal:)``
/// made of an envelope.
public enum HoldAnswer: UInt8, Hashable, Sendable {
    /// Not kept: acknowledge it.
    case notKept = 0
    /// Kept: acknowledge it.
    case kept = 1
    /// The hold on device seals is at its ceiling: kept for now without its
    /// seal. Stop the page here, unacknowledged, take what
    /// ``MLSClient/nextReopenable()`` hands out through, and drain again.
    case full = 2
}

/// What an envelope ``MLSClient/nextReopenable()`` handed out on its device
/// seal is to be made of (``MLSClient/heldDisposition(id:)``).
public enum HeldFate: UInt8, Hashable, Sendable {
    /// Taken through as any envelope: opened, then read, or drawn as a
    /// placeholder and asked for again.
    case ordinary = 0
    /// From a device of somebody who holds no leaf of the group any more: a
    /// placeholder naming them, neither opened nor asked for.
    case formerMember = 1
    /// For a group this device holds no copy of: a placeholder in the
    /// conversation of the group it opens to, naming its sender, asked for
    /// again once this device is seated there.
    case orphan = 2
}

extension HeldFate {
    /// The fate the core's `code` names. A code this binding does not know
    /// fails closed: never ``ordinary``, which would put the envelope
    /// through the group's door, but ``formerMember``, a placeholder that
    /// opens nothing and asks for nothing.
    public init(code: UInt8) {
        self = HeldFate(rawValue: code) ?? .formerMember
    }
}

/// ``HeldFate``, with the actor id of the person whose device sealed it;
/// `author` is nil when it is simply a leaf of the copy.
public struct HeldDisposition: Hashable, Sendable {
    public let fate: HeldFate
    public let author: String?

    public init(fate: HeldFate, author: String?) {
        self.fate = fate
        self.author = author
    }
}

/// An envelope ``MLSClient/holdEnvelope(mailboxKind:id:receivedAtMs:envelope:)``
/// kept that opens now, with the mailbox's own kind, id and receive time:
/// taken through the same path as a fresh one.
public struct HeldEnvelope: Hashable, Sendable {
    public let mailboxKind: UInt8
    public let receivedAtMs: UInt64
    public let id: String
    public let envelope: Data

    public init(mailboxKind: UInt8, receivedAtMs: UInt64, id: String, envelope: Data) {
        self.mailboxKind = mailboxKind
        self.receivedAtMs = receivedAtMs
        self.id = id
        self.envelope = envelope
    }
}
