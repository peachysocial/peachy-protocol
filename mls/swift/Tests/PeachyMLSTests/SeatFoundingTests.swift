// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// `seatFounding` across the C boundary: one commit seats every device, the
/// founder's own package rides in the same Welcome, and her copy opens
/// nothing. The protocol half is `mls/core/tests/founding_names_nobody.rs`.
final class SeatFoundingTests: XCTestCase {
    private let group = Data("peachy-founding".utf8)

    func testOneFoundingCommitSeatsEveryoneAndTheFoundersCopyOpensNothing() throws {
        let issuer = try TestIssuer(seed: 91)
        let ada = try issuer.client(actorId: "actor-ada", deviceId: "device-ada", tag: 31)
        let bo = try issuer.client(actorId: "actor-bo", deviceId: "device-bo", tag: 32)
        let cy = try issuer.client(actorId: "actor-cy", deviceId: "device-cy", tag: 33)

        XCTAssertEqual(MLSClient.foundingSeats, 32)
        try ada.createGroup(id: group)
        let own = try ada.generateKeyPackage()
        let boPackage = try bo.generateKeyPackage()
        let cyPackage = try cy.generateKeyPackage()
        // A second package for one device is left out, by index.
        XCTAssertEqual(
            try ada.foundingRefusals(groupID: group, keyPackages: [boPackage, cyPackage, boPackage]),
            [2])
        let founding = try ada.seatFounding(
            groupID: group, keyPackages: [boPackage, cyPackage], ownKeyPackage: own)
        try ada.mergePendingCommit(groupID: group)
        XCTAssertEqual(try ada.roster(groupID: group).count, 3)
        let welcome = try XCTUnwrap(founding.welcome)

        _ = try bo.join(welcome: welcome)
        _ = try cy.join(welcome: welcome)
        let hello = try ada.encrypt(groupID: group, plaintext: Data("hi".utf8))
        guard case let .application(heard, _, _) = try bo.processMessage(groupID: group, message: hello)
        else {
            return XCTFail("the message door should open an application message")
        }
        XCTAssertEqual(heard, Data("hi".utf8))

        XCTAssertThrowsError(try ada.join(welcome: welcome), "the founder's own copy opened")
    }
}
