// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// The group's own name and photo (`docs/sealed-messages.md` §The name is in the
/// group), driven through the Swift binding: the value round-trips as `Data`,
/// absent reads as `nil`, the other member reads it off its own tree, and a
/// joiner reads it out of the state it joined.
final class GroupMetaTests: XCTestCase {
    private let group = Data("peachy-swift-group-meta".utf8)
    private let named = Data(#"{"v":1,"n":"Book club"}"#.utf8)

    func testTheNameCrossesTheBindingAndReachesEveryMember() throws {
        let issuer = try TestIssuer(seed: 93)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 31)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 32)
        let cy = try issuer.client(actorId: "actor-cy", deviceId: "device-cy", tag: 33)
        try ada.createGroup(id: group)
        let add = try ada.addMember(groupID: group, keyPackage: try bo.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        _ = try bo.join(welcome: try XCTUnwrap(add.welcome))
        XCTAssertNil(try ada.groupMeta(groupID: group))

        // Bo is a plain member and renames anyway.
        let rename = try bo.setGroupMeta(groupID: group, value: named)
        XCTAssertNil(rename.welcome)
        XCTAssertNil(
            rename.commit.range(of: Data("Book club".utf8)),
            "the commit carries the name where the server can read it")
        XCTAssertNil(try bo.groupMeta(groupID: group), "staged, not adopted")
        _ = try ada.processCommit(groupID: group, message: rename.commit)
        try bo.mergePendingCommit(groupID: group)
        XCTAssertEqual(try ada.groupMeta(groupID: group), named)
        XCTAssertEqual(try bo.groupMeta(groupID: group), named)

        let seat = try ada.addMember(groupID: group, keyPackage: try cy.generateKeyPackage())
        try ada.mergePendingCommit(groupID: group)
        let welcome = try XCTUnwrap(seat.welcome)
        XCTAssertNil(welcome.range(of: Data("Book club".utf8)))
        _ = try cy.join(welcome: welcome)
        XCTAssertEqual(try cy.groupMeta(groupID: group), named)
    }

    func testAnEmptyValueIsRefusedAndStagesNothing() throws {
        let issuer = try TestIssuer(seed: 94)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 34)
        try ada.createGroup(id: group)
        XCTAssertThrowsError(try ada.setGroupMeta(groupID: group, value: Data())) { error in
            XCTAssertEqual((error as? MLSError)?.code, .invalidArgument)
        }
        XCTAssertFalse(try ada.hasPendingCommit(groupID: group))
    }
}
