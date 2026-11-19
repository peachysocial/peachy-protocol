// SPDX-License-Identifier: MIT
import Foundation
import PeachyMLSCore

// Encrypted calls (docs/calls.md §Keys, §Signaling, §Ringing;
// mls/core/src/call/). Everything here crosses the C door; nothing is
// re-implemented in Swift. Signals cross as the JSON form
// `mls/fixtures/calls.json` pins, and ``CallSignal`` is a typed view of it.

/// The numbers and labels every client agrees on, pinned by the fixture's
/// `constants` case.
public enum CallConstants {
    /// `call_root = MLS-Exporter(G, exporterLabel, call_id, 32)`.
    public static let exporterLabel = "peachy call v1"
    /// The ratchet salt the frame encryptor's key provider is configured with
    /// (HKDF-SHA256, 128 zero bytes of info, an AES-128-GCM key).
    public static let frameRatchetSalt = "peachy call frame v1"
    /// The key provider's ring: each epoch's keys go in slot `epoch mod 256`.
    public static let keyRingSize = 256
    /// How long the previous epoch's keys stay loaded after a rekey.
    public static let keyGraceMs = 10_000
    /// More members than this get a notice, not a ring.
    public static let ringCap = 16
    public static let ringTimeoutMs = 60_000
    public static let offerMaxAgeMs = 60_000
    /// Every device in a call commits its own self-update this often.
    public static let selfUpdateIntervalMs = 600_000
    public static let callIdBytes = 16
}

public enum CallMedia: String, Hashable, Sendable {
    case audio, video
}

/// Why a call ended for the device that sent it. The `*Elsewhere` reasons go
/// to the sender's own other devices.
public enum HangupReason: String, Hashable, Sendable {
    case normal
    case declined
    case busy
    case acceptedElsewhere = "accepted_elsewhere"
    case declinedElsewhere = "declined_elsewhere"
    case busyElsewhere = "busy_elsewhere"
    case needPermission = "need_permission"
}

/// One call signal: `Offer`, `Answer`, `Hangup`, `Remove`, `Direct`, `Left`,
/// `MediaKey` and the in-call controls travel as a signed MLS message through
/// the mailbox. A participant's first `Joined` at each epoch goes signed on
/// the MLS lane too, and only a signed one binds a participant; the
/// heartbeats after it go as live frames (docs/calls.md §The two
/// lanes).
public struct CallSignal: Hashable, Sendable {
    public enum Body: Hashable, Sendable {
        case offer(media: CallMedia, ring: Bool, createdAtMs: Int64)
        case answer
        case hangup(reason: HangupReason)
        /// `mediaKey` is the participant's 32-byte X25519 call public key,
        /// which a receiver requires and seals no grant to; `mediaKeyPq` is
        /// its 1,216-byte X-Wing call public key, in a signed `Joined` only,
        /// the key every grant is sealed to. The session and tracks are
        /// empty: they travel only in grants (docs/calls.md
        /// §Participant media keys). `startedAtMs` orders nothing.
        /// `participation` is the 24-byte mark (the participation's random
        /// id, then the device's counter): a receiver refuses a signed
        /// `Joined` without it, and one from an earlier participation than
        /// the one it bound at that leaf. The core fills in the keys,
        /// `startedAtMs` and the mark of every `Joined` it seals, whatever is
        /// passed.
        case joined(
            participantId: String, sessionId: String, trackNames: [String], leafIndex: UInt32,
            mediaKey: Data = Data(), startedAtMs: UInt64 = 0, mediaKeyPq: Data = Data(),
            participation: Data = Data())
        case left(participantId: String)
        case raiseHand(up: Bool)
        case react(emoji: String)
        case remoteMute(target: String)
        case remove(target: String)
        case media(audioOn: Bool, videoOn: Bool, presenting: Bool)
        /// A direct 1:1 call's session description, for the device at leaf
        /// `toLeaf` only (docs/calls.md §Direct 1:1 calls): the
        /// answering device's offer (`offer` true) or the caller's answer.
        /// MLS lane only, never urgent.
        case direct(toLeaf: UInt32, sdp: String, offer: Bool)
        /// v2: a participant's media secret at `generation`, sealed to each
        /// participant in `grants`. The core opens and applies it
        /// (``MLSClient/callMedia(groupID:request:)``); a client only sends
        /// what the core hands it. MLS lane only, never urgent.
        /// `startedAtMs` and `participation` are the granting participation's,
        /// as in its `Joined`: a grant counts only under the participation
        /// that sent it, and a signed `MediaKey` without the mark is refused.
        case mediaKey(
            generation: UInt32, rotated: Bool, grants: [CallMediaGrant], startedAtMs: UInt64 = 0,
            participation: Data = Data())
        /// A type a newer build sends. Ignored, never an error.
        case unknown
    }

    public var version: UInt32
    /// 16 random bytes.
    public var callId: Data
    public var body: Body

    public init(version: UInt32 = 1, callId: Data, body: Body) {
        self.version = version
        self.callId = callId
        self.body = body
    }

    /// Sent `urgent` through `SendSealed`: these wake a device.
    public var isUrgent: Bool {
        switch body {
        case .offer, .answer, .hangup: return true
        default: return false
        }
    }

    /// The JSON form, as the C door and the fixture read it.
    public func jsonObject() -> [String: Any] {
        var out: [String: Any] = ["version": Int(version), "callId": hex(callId)]
        switch body {
        case let .offer(media, ring, createdAtMs):
            out["type"] = "offer"
            out["media"] = media.rawValue
            out["ring"] = ring
            out["createdAtMs"] = createdAtMs
        case .answer:
            out["type"] = "answer"
        case let .hangup(reason):
            out["type"] = "hangup"
            out["reason"] = reason.rawValue
        case let .joined(
            participantId, sessionId, trackNames, leafIndex, mediaKey, startedAtMs, mediaKeyPq, participation):
            out["type"] = "joined"
            out["participantId"] = participantId
            out["sessionId"] = sessionId
            out["trackNames"] = trackNames
            out["leafIndex"] = Int(leafIndex)
            if !mediaKey.isEmpty { out["mediaKeyHex"] = hex(mediaKey) }
            if startedAtMs != 0 { out["startedAtMs"] = Int64(clamping: startedAtMs) }
            if !mediaKeyPq.isEmpty { out["mediaKeyPqHex"] = hex(mediaKeyPq) }
            if !participation.isEmpty { out["participationHex"] = hex(participation) }
        case let .mediaKey(generation, rotated, grants, startedAtMs, participation):
            out["type"] = "mediaKey"
            out["generation"] = Int(generation)
            out["rotated"] = rotated
            out["grants"] = grants.map {
                ["toLeaf": Int($0.toLeaf), "encHex": hex($0.enc), "ciphertextHex": hex($0.ciphertext)] as [String: Any]
            }
            if startedAtMs != 0 { out["startedAtMs"] = Int64(clamping: startedAtMs) }
            if !participation.isEmpty { out["participationHex"] = hex(participation) }
        case let .left(participantId):
            out["type"] = "left"
            out["participantId"] = participantId
        case let .raiseHand(up):
            out["type"] = "raiseHand"
            out["up"] = up
        case let .react(emoji):
            out["type"] = "react"
            out["emoji"] = emoji
        case let .remoteMute(target):
            out["type"] = "remoteMute"
            out["target"] = target
        case let .remove(target):
            out["type"] = "remove"
            out["target"] = target
        case let .media(audioOn, videoOn, presenting):
            out["type"] = "media"
            out["audioOn"] = audioOn
            out["videoOn"] = videoOn
            out["presenting"] = presenting
        case let .direct(toLeaf, sdp, offer):
            out["type"] = "direct"
            out["toLeaf"] = Int(toLeaf)
            out["sdp"] = sdp
            out["offer"] = offer
        case .unknown:
            out["type"] = "unknown"
        }
        return out
    }

    public func jsonString() throws -> String {
        let data = try JSONSerialization.data(withJSONObject: jsonObject(), options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    /// Read the JSON form. Throws `invalidArgument` on a shape this build
    /// cannot read (the core has already refused anything malformed on the
    /// wire, so this is a programming error, not hostile input).
    public init(jsonObject object: [String: Any]) throws {
        func bad(_ what: String) -> MLSError {
            MLSError(code: .invalidArgument, message: "could not read the call signal: \(what)")
        }
        func string(_ key: String) throws -> String {
            guard let value = object[key] as? String else { throw bad("`\(key)` is a string") }
            return value
        }
        // JSONSerialization hands back NSNumber for both, and a 0 or 1 casts
        // to Bool under `is Bool`; only the CFBoolean type id tells them apart.
        func isBoolean(_ value: Any?) -> Bool {
            guard let number = value as? NSNumber else { return false }
            return CFGetTypeID(number) == CFBooleanGetTypeID()
        }
        func bool(_ key: String, default fallback: Bool? = nil) throws -> Bool {
            if isBoolean(object[key]), let value = object[key] as? Bool { return value }
            if let fallback, object[key] == nil { return fallback }
            throw bad("`\(key)` is a boolean")
        }
        func number(_ key: String, default fallback: Int64? = nil) throws -> Int64 {
            if let value = object[key] as? NSNumber, !isBoolean(value) { return value.int64Value }
            if let fallback, object[key] == nil { return fallback }
            throw bad("`\(key)` is a number")
        }
        let version = (object["version"] as? NSNumber)?.uint32Value ?? 1
        guard let callId = unhex(try string("callId")), callId.count == CallConstants.callIdBytes else {
            throw bad("a call id is 16 bytes of hex")
        }
        func bytes(_ key: String) throws -> Data {
            guard let text = object[key] as? String else { return Data() }
            guard let value = unhex(text) else { throw bad("`\(key)` is hex") }
            return value
        }
        let body: Body
        switch try string("type") {
        case "offer":
            guard let media = CallMedia(rawValue: try string("media")) else { throw bad("media") }
            body = .offer(
                media: media,
                ring: try bool("ring", default: false),
                createdAtMs: try number("createdAtMs", default: 0)
            )
        case "answer":
            body = .answer
        case "hangup":
            guard let reason = HangupReason(rawValue: try string("reason")) else { throw bad("reason") }
            body = .hangup(reason: reason)
        case "joined":
            body = .joined(
                participantId: try string("participantId"),
                sessionId: try string("sessionId"),
                trackNames: object["trackNames"] as? [String] ?? [],
                leafIndex: UInt32(truncatingIfNeeded: try number("leafIndex")),
                mediaKey: try bytes("mediaKeyHex"),
                startedAtMs: UInt64(clamping: try number("startedAtMs", default: 0)),
                mediaKeyPq: try bytes("mediaKeyPqHex"),
                participation: try bytes("participationHex")
            )
        case "mediaKey":
            let grants = try (object["grants"] as? [[String: Any]] ?? []).map { grant -> CallMediaGrant in
                guard let toLeaf = grant["toLeaf"] as? NSNumber,
                      let enc = (grant["encHex"] as? String).flatMap(unhex),
                      let ciphertext = (grant["ciphertextHex"] as? String).flatMap(unhex)
                else { throw bad("a grant is {toLeaf, encHex, ciphertextHex}") }
                return CallMediaGrant(toLeaf: toLeaf.uint32Value, enc: enc, ciphertext: ciphertext)
            }
            body = .mediaKey(
                generation: UInt32(truncatingIfNeeded: try number("generation", default: 0)),
                rotated: try bool("rotated", default: false),
                grants: grants,
                startedAtMs: UInt64(clamping: try number("startedAtMs", default: 0)),
                participation: try bytes("participationHex")
            )
        case "left":
            body = .left(participantId: try string("participantId"))
        case "raiseHand":
            body = .raiseHand(up: try bool("up"))
        case "react":
            body = .react(emoji: try string("emoji"))
        case "remoteMute":
            body = .remoteMute(target: try string("target"))
        case "remove":
            body = .remove(target: try string("target"))
        case "media":
            body = .media(
                audioOn: try bool("audioOn"),
                videoOn: try bool("videoOn"),
                presenting: try bool("presenting", default: false)
            )
        case "direct":
            body = .direct(
                toLeaf: UInt32(truncatingIfNeeded: try number("toLeaf")),
                sdp: try string("sdp"),
                offer: try bool("offer", default: false)
            )
        case "unknown":
            body = .unknown
        case let other:
            throw bad("unknown type \(other)")
        }
        self.init(version: version, callId: callId, body: body)
    }

    public init(jsonString: String) throws {
        guard let object = try JSONSerialization.jsonObject(with: Data(jsonString.utf8)) as? [String: Any] else {
            throw MLSError(code: .invalidArgument, message: "a call signal is a JSON object")
        }
        try self.init(jsonObject: object)
    }
}

/// One participant's sealed copy of a ``CallSignal/Body/mediaKey(generation:rotated:grants:startedAtMs:participation:)``.
public struct CallMediaGrant: Hashable, Sendable {
    public let toLeaf: UInt32
    /// The HPKE encapsulated key: 1,120 bytes for the X-Wing grant a sender
    /// makes; 32 for a classical one, which no receiver opens.
    public let enc: Data
    public let ciphertext: Data

    public init(toLeaf: UInt32, enc: Data, ciphertext: Data) {
        self.toLeaf = toLeaf
        self.enc = enc
        self.ciphertext = ciphertext
    }
}

/// One sender's frame key for one epoch.
public struct CallSenderKey: Hashable, Sendable {
    public let leafIndex: UInt32
    /// 16 bytes: what goes into the frame encryptor's key provider for this
    /// participant at ``CallKeys/keyIndex``.
    public let key: Data
}

/// A call's keys at one epoch.
public struct CallKeys: Hashable, Sendable {
    public let epoch: UInt64
    /// The key provider slot: `epoch mod 256`.
    public let keyIndex: UInt8
    /// `MLS-Exporter(G, "peachy call v1", call_id, 32)`; a leaf a staged
    /// commit adds derives with ``MLSClient/callSenderKey(callRoot:leafIndex:)``.
    public let callRoot: Data
    /// Every leaf in the tree, in leaf order.
    public let senders: [CallSenderKey]

    /// Read the C door's packed form:
    /// `epoch u64be ‖ key_index u8 ‖ root[32] ‖ count u32be ‖ (leaf u32be ‖ key[16])*`.
    init(packed: Data) throws {
        let bytes = [UInt8](packed)
        func bad() -> MLSError {
            MLSError(code: .invalidArgument, message: "the call keys are not in the packed form")
        }
        func be(_ at: Int, _ width: Int) -> UInt64 {
            bytes[at..<(at + width)].reduce(0) { ($0 << 8) | UInt64($1) }
        }
        guard bytes.count >= 45 else { throw bad() }
        epoch = be(0, 8)
        keyIndex = bytes[8]
        callRoot = Data(bytes[9..<41])
        let count = Int(be(41, 4))
        guard bytes.count == 45 + count * 20 else { throw bad() }
        senders = (0..<count).map { index in
            let at = 45 + index * 20
            return CallSenderKey(
                leafIndex: UInt32(be(at, 4)),
                key: Data(bytes[(at + 4)..<(at + 20)])
            )
        }
    }
}

/// A call envelope's signal, opened.
public struct OpenedCallSignal: Hashable, Sendable {
    public enum Lane: String, Hashable, Sendable { case mls, live }
    public let lane: Lane
    /// The MLS lane's authenticated sender; `nil` on the live lane.
    public let sender: Identity?
    /// The sender's leaf index, on the MLS lane.
    public let senderLeaf: UInt32?
    public let urgent: Bool
    public let signal: CallSignal
    /// v2: the envelopes this device owes now (grants to a newcomer, or a
    /// rotation after a leaver), each for `SendSealed`, not urgent, in order.
    public var send: [Data] = []
    /// v2: what a `MediaKey` granted this device, as the core's JSON
    /// (`{"senderLeaf","generation","sessionId","trackNames","bound"}`), or nil.
    public var mediaJSON: String? = nil
    /// v2: the leaf a signed `Left` unbound (its sender's own), or nil when it
    /// unbound nothing. A client drops a tile for a signed `Left` only at
    /// this leaf (docs/calls.md R-K10).
    public var unboundLeaf: UInt32? = nil
}

extension MLSClient {
    /// The call's keys at the group's current epoch. Call again on every
    /// epoch change, keeping the previous ring for ``CallConstants/keyGraceMs``.
    public func callKeys(groupID: Data, callId: Data) throws -> CallKeys {
        try callKeys(groupID: groupID, callId: callId, pending: false)
    }

    /// The keys at the epoch this client's STAGED commit moves the group to,
    /// so the committer can load them before the first frame under them.
    public func pendingCallKeys(groupID: Data, callId: Data) throws -> CallKeys {
        try callKeys(groupID: groupID, callId: callId, pending: true)
    }

    private func callKeys(groupID: Data, callId: Data, pending: Bool) throws -> CallKeys {
        let packed: Data = try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try withBytes(callId) { call, callLength in
                    try check(
                        peachy_mls_group_call_keys(
                            handle, group, groupLength, call, callLength, pending, &buffer
                        )
                    )
                }
            }
            return takeData(&buffer)
        }
        return try CallKeys(packed: packed)
    }

    /// Seal a call signal: the whole kind-6 envelope, ready for `SendSealed`
    /// (`urgent` when ``CallSignal/isUrgent``). An MLS-lane signal advances
    /// the sender ratchet, like ``encrypt(groupID:plaintext:)``.
    public func sealCallSignal(groupID: Data, _ signal: CallSignal) throws -> Data {
        let json = try signal.jsonString()
        return try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try json.withCString { text in
                    try check(peachy_mls_group_call_seal(handle, group, groupLength, text, &buffer))
                }
            }
            return takeData(&buffer)
        }
    }

    /// Seal ANY call signal on the MLS lane, sender-authenticated. A
    /// participant's first `Joined` in each epoch goes this way, so receivers
    /// bind its tracks to its own leaf (docs/calls.md, D10).
    /// Send through `SendSealed`, not urgent.
    public func sealCallSignalSigned(groupID: Data, _ signal: CallSignal) throws -> Data {
        let json = try signal.jsonString()
        return try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try json.withCString { text in
                    try check(peachy_mls_group_call_seal_signed(handle, group, groupLength, text, &buffer))
                }
            }
            return takeData(&buffer)
        }
    }

    /// Open the inner bytes of an envelope ``openEnvelope(_:)`` returned with
    /// kind ``EnvelopeKind/call``.
    public func openCallSignal(groupID: Data, inner: Data) throws -> OpenedCallSignal {
        let json: String = try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try withBytes(inner) { bytes, length in
                    try check(
                        peachy_mls_group_call_open(handle, group, groupLength, bytes, length, &buffer)
                    )
                }
            }
            return takeString(&buffer)
        }
        guard
            let object = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any],
            let lane = (object["lane"] as? String).flatMap(OpenedCallSignal.Lane.init(rawValue:)),
            let signal = object["signal"] as? [String: Any]
        else {
            throw MLSError(code: .invalidArgument, message: "could not read the opened call signal")
        }
        var sender: Identity?
        if let who = object["sender"] as? [String: Any],
           let actor = who["actorId"] as? String,
           let device = who["deviceId"] as? String {
            sender = Identity(actorId: actor, deviceId: device)
        }
        var mediaJSON: String?
        if let media = object["media"] as? [String: Any] {
            let data = try JSONSerialization.data(withJSONObject: media, options: [.sortedKeys])
            mediaJSON = String(decoding: data, as: UTF8.self)
        }
        return OpenedCallSignal(
            lane: lane,
            sender: sender,
            senderLeaf: (object["senderLeaf"] as? NSNumber)?.uint32Value,
            urgent: object["urgent"] as? Bool ?? false,
            signal: try CallSignal(jsonObject: signal),
            send: (object["send"] as? [String] ?? []).compactMap(unhex),
            mediaJSON: mediaJSON,
            unboundLeaf: (object["unboundLeaf"] as? NSNumber)?.uint32Value
        )
    }

    /// A v2 call's participant media keys (docs/calls.md
    /// §Participant media keys) through the core's one JSON door: `op` is
    /// `start` (with `participantId`, the server's answer to JoinCall),
    /// `share`, `remove`, `epoch`, `apply`, `end` or `keys`, and the
    /// answer is the core's JSON. `remove` with a `participantId` (an
    /// admin's honored `Remove`) unbinds that id for the rest of the call.
    /// Each `send` entry it returns is a whole envelope for
    /// `SendSealed`, not urgent. `keys` throws "call state lost" (as sealing
    /// a `Joined` does) when this core holds no participation in the call:
    /// join again (`start`, a signed `Joined`, `share`).
    public func callMedia(groupID: Data, request: String) throws -> String {
        try locked { handle in
            var buffer = PeachyMlsBuffer()
            try withBytes(groupID) { group, groupLength in
                try request.withCString { text in
                    try check(peachy_mls_group_call_media(handle, group, groupLength, text, &buffer))
                }
            }
            return takeString(&buffer)
        }
    }

    // MARK: - No client

    /// A call signal (JSON form) to its protobuf bytes.
    public static func encodeCallSignal(json: String) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try json.withCString { text in
            try checkStatus(peachy_mls_call_signal_encode(text, &buffer))
        }
        return takeData(&buffer)
    }

    /// Protobuf bytes to the JSON form; an unknown type reads as `"unknown"`.
    public static func decodeCallSignal(_ bytes: Data) throws -> String {
        var buffer = PeachyMlsBuffer()
        try withBytes(bytes) { pointer, length in
            try checkStatus(peachy_mls_call_signal_decode(pointer, length, &buffer))
        }
        return takeString(&buffer)
    }

    /// One sender's 16-byte key from a 32-byte call root.
    public static func callSenderKey(callRoot: Data, leafIndex: UInt32) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try withBytes(callRoot) { pointer, length in
            try checkStatus(peachy_mls_call_sender_key(pointer, length, leafIndex, &buffer))
        }
        return takeData(&buffer)
    }

    /// The AES-128-GCM key a frame encryptor derives from a sender key (HKDF
    /// under ``CallConstants/frameRatchetSalt``), for checking a native
    /// provider's derivation or encrypting frames without one.
    public static func callFrameKey(senderKey: Data) throws -> Data {
        var buffer = PeachyMlsBuffer()
        try withBytes(senderKey) { pointer, length in
            try checkStatus(peachy_mls_call_frame_key(pointer, length, &buffer))
        }
        return takeData(&buffer)
    }

    /// The stagger of this device's in-call self-updates: commit its own
    /// `selfUpdate` at `joined + offset + k * 600 s`. `rank` is its position
    /// among the participants by ascending leaf index.
    public static func callSelfUpdateOffsetMs(rank: UInt32, participants: UInt32) throws -> UInt64 {
        var offset: UInt64 = 0
        try checkStatus(peachy_mls_call_self_update_offset_ms(rank, participants, &offset))
        return offset
    }

    /// One step of the ring-state reducer: state JSON (`nil` for idle) and
    /// event JSON in, `{"state","effects"}` JSON out. Pure; the caller keeps
    /// the state and performs the effects.
    public static func callRingStep(state: String?, event: String) throws -> String {
        var buffer = PeachyMlsBuffer()
        try event.withCString { eventText in
            if let state {
                try state.withCString { stateText in
                    try checkStatus(peachy_mls_call_ring_step(stateText, eventText, &buffer))
                }
            } else {
                try checkStatus(peachy_mls_call_ring_step(nil, eventText, &buffer))
            }
        }
        return takeString(&buffer)
    }
}

private func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func unhex(_ text: String) -> Data? {
    guard text.count % 2 == 0 else { return nil }
    var out = Data(capacity: text.count / 2)
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
        out.append(byte)
        index = next
    }
    return out
}
