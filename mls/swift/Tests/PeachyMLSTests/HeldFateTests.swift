// SPDX-License-Identifier: MIT
import XCTest

@testable import PeachyMLS

/// A held envelope's fate code from the core, decoded. The apps put an
/// envelope through the group's door only for ``HeldFate/ordinary``, so a
/// code this binding does not know must never decode to it.
final class HeldFateTests: XCTestCase {
    func testKnownCodesDecodeToTheirOwnFate() {
        XCTAssertEqual(HeldFate(code: 0), .ordinary)
        XCTAssertEqual(HeldFate(code: 1), .formerMember)
        XCTAssertEqual(HeldFate(code: 2), .orphan)
    }

    func testAnUnknownCodeFailsClosed() {
        for code: UInt8 in [3, 7, 128, 255] {
            XCTAssertEqual(HeldFate(code: code), .formerMember, "code \(code)")
        }
    }
}
