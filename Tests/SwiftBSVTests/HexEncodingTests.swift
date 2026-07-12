import XCTest
@testable import SwiftBSV

/// Pins `Data.hex` after the O(n) rewrite (2026-07-12). The previous
/// per-byte `reduce` + string concatenation was quadratic — invisible on a
/// payment-sized transaction, unable to finish on a 32 MB inscription. The
/// large round-trip below doubles as the regression guard: the old form
/// would hang the suite at this size.
final class HexEncodingTests: XCTestCase {

    func testKnownVector() {
        XCTAssertEqual(Data([0x00, 0x0f, 0xa0, 0xff]).hex, "000fa0ff")
    }

    func testEmpty() {
        XCTAssertEqual(Data().hex, "")
    }

    func testMatchesReferenceOnRandomBytes() {
        var seed: UInt64 = 0x9E37_79B9_7F4A_7C15
        let bytes = (0..<4096).map { _ -> UInt8 in
            seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            return UInt8(truncatingIfNeeded: seed >> 32)
        }
        let data = Data(bytes)
        let reference = bytes.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(data.hex, reference)
    }

    func testSlicePreservesContent() {
        // A Data slice has a non-zero startIndex — iteration must still
        // encode the slice's own bytes, not the parent's.
        let parent = Data([0xde, 0xad, 0xbe, 0xef])
        XCTAssertEqual(parent[1...2].hex, "adbe")
    }

    func testLargeRoundTrip() {
        var seed: UInt64 = 42
        var bytes = [UInt8](repeating: 0, count: 1 << 20)
        for i in bytes.indices {
            seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            bytes[i] = UInt8(truncatingIfNeeded: seed >> 32)
        }
        let data = Data(bytes)
        let encoded = data.hex
        XCTAssertEqual(encoded.count, data.count * 2)
        XCTAssertEqual(Data(hex: encoded), data)
    }
}
