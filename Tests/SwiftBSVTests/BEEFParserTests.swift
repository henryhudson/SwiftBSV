//
//  BEEFParserTests.swift
//  SwiftBSVTests
//
//  Bounds-safety of `BEEFParser.parse` against hostile script-length
//  varints. BEEF arrives from untrusted peers (BRC-100 internalizeAction),
//  so a malformed envelope must throw — never trap.
//

import XCTest
@testable import SwiftBSV

final class BEEFParserTests: XCTestCase {

    /// BEEF version marker `0x0100BEEF` (little-endian) followed by an
    /// nBumps varint of 0 — the common prefix of every fixture below.
    private let header = "efbe0001" + "00"

    func testParseThrowsOnOverflowingInputScriptLength() {
        // One tx: version, one input (32-byte txid + 4-byte index), then an
        // input-script-length varint of UInt64.max. The old code did
        // `Int(scriptLen)`, which traps before any bounds check can run.
        let beef = Data(hex: header
            + "01"                                  // tx count = 1
            + "01000000"                            // tx version
            + "01"                                  // input count = 1
            + String(repeating: "00", count: 32)    // prev txid
            + "00000000"                            // prev index
            + "ffffffffffffffffff")                 // script length varint = UInt64.max
        XCTAssertThrowsError(try BEEFParser.parse(data: beef)) { error in
            guard case BEEFParser.ParseError.invalidData = error else {
                return XCTFail("expected ParseError.invalidData, got \(error)")
            }
        }
    }

    func testParseThrowsOnOverflowingOutputScriptLength() {
        // One tx: version, zero inputs, one output (8-byte value), then an
        // output-script-length varint of Int.max. `Int(scriptLen)` succeeds
        // here, but `offset + Int.max` would overflow-trap.
        let beef = Data(hex: header
            + "01"                                  // tx count = 1
            + "01000000"                            // tx version
            + "00"                                  // input count = 0
            + "01"                                  // output count = 1
            + "0000000000000000"                    // value (satoshis)
            + "ffffffffffffffff7f")                 // script length varint = Int.max
        XCTAssertThrowsError(try BEEFParser.parse(data: beef)) { error in
            guard case BEEFParser.ParseError.invalidData = error else {
                return XCTFail("expected ParseError.invalidData, got \(error)")
            }
        }
    }

    func testParseThrowsOnTruncatedScript() {
        // Input script length claims 16 bytes; only 2 follow. A representable
        // length that runs past the buffer must throw `.unexpectedEnd` — the
        // truncation behaviour the bounds-safe rewrite has to preserve.
        let beef = Data(hex: header
            + "01"                                  // tx count = 1
            + "01000000"                            // tx version
            + "01"                                  // input count = 1
            + String(repeating: "00", count: 32)    // prev txid
            + "00000000"                            // prev index
            + "10"                                  // script length = 16
            + "0000")                               // only 2 of the 16 bytes
        XCTAssertThrowsError(try BEEFParser.parse(data: beef)) { error in
            guard case BEEFParser.ParseError.unexpectedEnd = error else {
                return XCTFail("expected ParseError.unexpectedEnd, got \(error)")
            }
        }
    }

    func testParseRoundTripsAValidBEEF() throws {
        let validRawTx = Data(hex: "01000000014b943d0e6275f29958760eb5977696023a99df63ee5977698053136fa03a10b9020000006a47304402204cbb8b541a9c62c9e27ab4a3b87bd8e0f4b63199438ba45283c93d5ad0ef7fe202207899680061109622c633d1786ea7e090d24517ff3109192033989da86054073b41210265bc3edcf9823e9c5e74a2bb9c1cf29b2515324b423d99bc059a534af5f240e2ffffffff0300000000000000001a006a1748656c6c6f2c20796f75206172652077656c636f6d652ee8030000000000001976a914f8660a6a535732d80060e64e4aa1c8e402ecc91f88acf36eaf44000000001976a914fe5e3903387a194385ee6f5413bf825f709b1e0088ac00000000")
        let beef = BEEF(bumps: [], transactions: [
            BEEFTransaction(rawTx: validRawTx, hasBUMP: false, bumpIndex: nil)
        ])
        let parsed = try BEEFParser.parse(data: BEEFParser.serialize(beef))
        XCTAssertEqual(parsed.transactions.count, 1)
        XCTAssertEqual(parsed.transactions.first?.rawTx, validRawTx)
    }
}
