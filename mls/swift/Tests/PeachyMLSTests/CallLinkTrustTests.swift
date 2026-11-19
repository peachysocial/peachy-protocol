// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// A call link's client adopts the main client's own-device trust through
/// this binding (docs/calls.md §Call links on participant keys). The
/// protocol half is `mls/core/tests/call_link_own_devices.rs`; this holds
/// that the three doors cross intact: a device the main client forgot is
/// refused by the link's client too, another device's trust is refused, and
/// an own leaf on no chain is not the person's.
final class CallLinkTrustTests: XCTestCase {
    private let group = Data("88888888-8888-4888-8888-888888888888".utf8)

    func testALinkClientAdoptsTheMainClientsForgottenDevices() throws {
        let issuer = try TestIssuer(seed: 83)
        let main = try issuer.client(actorId: "actor-ada", deviceId: "device-ada-laptop", tag: 31)
        let link = try issuer.client(actorId: "actor-ada", deviceId: "device-ada-laptop", tag: 31)
        let phone = try issuer.client(actorId: "actor-ada", deviceId: "device-ada-phone", tag: 32)
        let tablet = try issuer.client(actorId: "actor-ada", deviceId: "device-ada-tablet", tag: 33)
        let phoneKey = try MLSClient.signingKeyPublicKey(seed: TestIssuer.deviceSeed(32))
        let tabletKey = try MLSClient.signingKeyPublicKey(seed: TestIssuer.deviceSeed(33))
        let laptopKey = try MLSClient.signingKeyPublicKey(seed: TestIssuer.deviceSeed(31))
        try main.forgetOwnDevice(deviceId: "device-ada-phone", signingKey: phoneKey)

        XCTAssertThrowsError(try link.adoptOwnDeviceTrust(try tablet.ownDeviceTrust()))
        try link.adoptOwnDeviceTrust(try main.ownDeviceTrust())

        XCTAssertEqual(
            link.ownDeviceStanding(actorId: "actor-ada", deviceId: "device-ada-phone", deviceKey: phoneKey),
            .forgotten)
        XCTAssertEqual(
            link.ownDeviceStanding(actorId: "actor-ada", deviceId: "device-ada-tablet", deviceKey: tabletKey),
            .offChain)
        XCTAssertEqual(
            link.ownDeviceStanding(actorId: "actor-ada", deviceId: "device-ada-laptop", deviceKey: laptopKey),
            .thisDevice)
        XCTAssertEqual(
            link.ownDeviceStanding(actorId: "actor-bo", deviceId: "device-bo", deviceKey: tabletKey), .notOwn)
        XCTAssertFalse(OwnDeviceStanding.offChain.countsAsOwn)
        XCTAssertTrue(OwnDeviceStanding.onChain.countsAsOwn)

        try link.createGroup(id: group)
        XCTAssertThrowsError(try link.addMember(groupID: group, keyPackage: try phone.generateKeyPackage()))
    }
}
