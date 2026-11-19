// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// `processMessage` and `processCommit` across the C boundary: a commit at the
/// message door, or an application message at the commit door, throws
/// `.wrongDoor` and moves nothing. The protocol half is
/// `mls/core/tests/doors.rs`; this holds that the door and the new code cross
/// this binding intact.
final class DoorTests: XCTestCase {
    private let group = Data("peachy-doors".utf8)

    func testACommitAtTheMessageDoorIsRefusedAndTheCommitDoorTakesIt() throws {
        let issuer = try TestIssuer(seed: 81)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 21)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 22)

        try ada.createGroup(id: group)
        let added = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(added.welcome))

        let update = try ada.selfUpdate(groupID: group)
        try ada.mergePendingCommit(groupID: group)

        XCTAssertThrowsError(try bo.processMessage(groupID: group, message: update.commit)) { error in
            XCTAssertEqual((error as? MLSError)?.code, .wrongDoor)
        }
        XCTAssertEqual(try bo.epoch(groupID: group), 1, "the refused commit moved nothing")

        guard case .commit = try bo.processCommit(groupID: group, message: update.commit) else {
            return XCTFail("the commit door should take a commit")
        }
        XCTAssertEqual(try bo.epoch(groupID: group), 2)

        let hello = try ada.encrypt(groupID: group, plaintext: Data("hi".utf8))
        XCTAssertThrowsError(try bo.processCommit(groupID: group, message: hello)) { error in
            XCTAssertEqual((error as? MLSError)?.code, .wrongDoor)
        }
        // Refused before it was decrypted: the message door still opens it.
        guard case let .application(heard, _, _) = try bo.processMessage(groupID: group, message: hello)
        else {
            return XCTFail("the message door should open an application message")
        }
        XCTAssertEqual(heard, Data("hi".utf8))
    }

    /// THE MAILBOX DOOR: a commit sealed into an MLS entry, one the arbiter
    /// never ordered, is refused by the core whatever the caller does with
    /// the sealed kind, and moves nothing; the same commit from a COMMIT
    /// entry is taken. A message from a COMMIT entry, and a seat ask, are
    /// refused too.
    func testTheMailboxDoorTakesACommitOnlyFromACommitEntry() throws {
        let issuer = try TestIssuer(seed: 83)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 23)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 24)

        try ada.createGroup(id: group)
        let added = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(added.welcome))

        let update = try ada.selfUpdate(groupID: group)
        try ada.mergePendingCommit(groupID: group)

        XCTAssertThrowsError(
            try bo.processMailboxEntry(
                groupID: group, mailboxKind: MailboxKind.mls, envelopeKind: EnvelopeKind.commit,
                inner: update.commit)
        ) { error in
            XCTAssertEqual((error as? MLSError)?.code, .wrongDoor)
        }
        XCTAssertEqual(try bo.epoch(groupID: group), 1, "a commit from an MLS entry moved the group")

        guard
            case .commit = try bo.processMailboxEntry(
                groupID: group, mailboxKind: MailboxKind.commit, envelopeKind: EnvelopeKind.commit,
                inner: update.commit)
        else {
            return XCTFail("a commit from a COMMIT entry should be taken")
        }
        XCTAssertEqual(try bo.epoch(groupID: group), 2)

        let hello = try ada.encrypt(groupID: group, plaintext: Data("hi".utf8))
        for (mailbox, kind) in [
            (MailboxKind.commit, EnvelopeKind.message), (MailboxKind.mls, EnvelopeKind.seatAsk),
        ] {
            XCTAssertThrowsError(
                try bo.processMailboxEntry(groupID: group, mailboxKind: mailbox, envelopeKind: kind, inner: hello)
            ) { error in
                XCTAssertEqual((error as? MLSError)?.code, .wrongDoor)
            }
        }
        guard
            case let .application(heard, _, _) = try bo.processMailboxEntry(
                groupID: group, mailboxKind: MailboxKind.mls, envelopeKind: EnvelopeKind.message, inner: hello)
        else {
            return XCTFail("a message from an MLS entry should open")
        }
        XCTAssertEqual(heard, Data("hi".utf8))
    }

    /// `envelopeDoor` crosses the boundary as the core's table.
    func testTheEnvelopeDoorIsTheCoresTable() {
        XCTAssertEqual(
            MLSClient.envelopeDoor(mailboxKind: MailboxKind.commit, envelopeKind: EnvelopeKind.commit), .commit)
        XCTAssertEqual(
            MLSClient.envelopeDoor(mailboxKind: MailboxKind.mls, envelopeKind: EnvelopeKind.commit), .drop)
        XCTAssertEqual(
            MLSClient.envelopeDoor(mailboxKind: MailboxKind.mls, envelopeKind: EnvelopeKind.message), .message)
        XCTAssertEqual(
            MLSClient.envelopeDoor(mailboxKind: MailboxKind.mls, envelopeKind: EnvelopeKind.seatAsk), .seatAsk)
        XCTAssertEqual(MLSClient.envelopeDoor(mailboxKind: MailboxKind.mls, envelopeKind: EnvelopeKind.call), .call)
        XCTAssertEqual(
            MLSClient.envelopeDoor(mailboxKind: MailboxKind.commit, envelopeKind: EnvelopeKind.message), .drop)
    }
}
