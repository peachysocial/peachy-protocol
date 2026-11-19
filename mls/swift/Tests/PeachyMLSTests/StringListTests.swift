// SPDX-License-Identifier: MIT
import Foundation
import XCTest

@testable import PeachyMLS

/// THE STRING LIST the C door hands id lists across in (`encodeStringList` /
/// `decodeStringList`, MLSClient.swift): a u32 big-endian count, then each item
/// as a u32 big-endian length and its UTF-8 bytes. Read strictly: a buffer
/// that does not hold exactly that throws, never answers part of a list.
final class StringListTests: XCTestCase {
    func testItRoundTripsAndFramesEveryItem() throws {
        let lists: [[String]] = [[], [""], ["device-ada"], ["a\nb", "c#d", "nul\u{0}", "ünï"], ["", "x", ""]]
        for items in lists {
            XCTAssertEqual(try decodeStringList(encodeStringList(items)), items)
        }
        XCTAssertEqual(
            encodeStringList(["ab", ""]),
            Data([0, 0, 0, 2, 0, 0, 0, 2, 0x61, 0x62, 0, 0, 0, 0]))
    }

    func testAnEmptyBufferIsTheEmptyList() throws {
        XCTAssertEqual(try decodeStringList(Data()), [])
        XCTAssertEqual(try decodeStringList(Data([0, 0, 0, 0])), [])
    }

    func testAMalformedBufferThrows() {
        let malformed: [Data] = [
            Data([0, 0, 0]),  // a truncated count
            Data([0, 0, 0, 1]),  // a count with no item
            Data([0, 0, 0, 1, 0, 0]),  // a truncated length
            Data([0, 0, 0, 1, 0, 0, 0, 3, 0x61, 0x62]),  // a truncated item
            Data([0, 0, 0, 1, 0, 0, 0, 1, 0x61, 0x62]),  // a trailing byte
            Data([0, 0, 0, 0, 0]),  // bytes after an empty list
            Data([0, 0, 0, 1, 0, 0, 0, 1, 0xFF]),  // not UTF-8
            Data([0xFF, 0xFF, 0xFF, 0xFF]),  // a count the buffer cannot hold
        ]
        for data in malformed {
            XCTAssertThrowsError(try decodeStringList(data), "\(Array(data))") { error in
                XCTAssertEqual((error as? MLSError)?.code, .codec)
            }
        }
    }
}
