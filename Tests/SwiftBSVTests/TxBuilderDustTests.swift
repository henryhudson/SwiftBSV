//
//  TxBuilderDustTests.swift
//  SwiftBSV
//

import Foundation
import XCTest
@testable import SwiftBSV

class TxBuilderDustTests: XCTestCase {

    /// One 10,000-satoshi input, one 9,700-satoshi payment at 50 sat/kB:
    /// the fee is about 12 satoshis, so roughly 288 satoshis of change is
    /// left — below the default 546 dust floor.
    private func buildSmallChange(dust: UInt64?) throws -> TxBuilder {
        let key = PrivateKey(data: Data(repeating: 0x11, count: 32))
        let payee = PrivateKey(data: Data(repeating: 0x22, count: 32))
        let txOut = TransactionOutput(value: 10_000,
                                      lockingScript: key.publicKey.address.toTxOutputScript().data)

        var txb = TxBuilder()
            .setFeePerKb(50)
            .setChangeAddress(key.publicKey.address)
        if let dust { txb = txb.setDust(dust) }
        txb.inputFromPubKeyHash(txHashBuffer: Data(repeating: 0xab, count: 32),
                                txOutNum: 0, txOut: txOut, pubKey: key.publicKey)
        txb.outputToAddress(value: 9_700, address: payee.publicKey.address)
        try txb.build(useAllInputs: true)
        return txb
    }

    func testDefaultDustSendsSmallChangeToFees() throws {
        let txb = try buildSmallChange(dust: nil)
        XCTAssertEqual(txb.transaction.outputs.count, 1)
        XCTAssertEqual(txb.changeAmount, 0)
        XCTAssertEqual(txb.feeAmount, 300)
    }

    func testLowerDustKeepsSmallChange() throws {
        let txb = try buildSmallChange(dust: 2)
        XCTAssertEqual(txb.transaction.outputs.count, 2)
        XCTAssertGreaterThan(txb.changeAmount, 0)
        XCTAssertEqual(txb.transaction.outputs[1].value, txb.changeAmount)
        XCTAssertEqual(txb.changeAmount + txb.feeAmount, 300)
        XCTAssertLessThan(txb.feeAmount, 20)
    }

    func testChangeBelowTheLowerFloorStillGoesToFees() throws {
        let txb = try buildSmallChange(dust: 1_000)
        XCTAssertEqual(txb.transaction.outputs.count, 1)
        XCTAssertEqual(txb.feeAmount, 300)
    }
}
