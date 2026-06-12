//
//  ScriptContextSurfaceTests.swift
//
//  Copyright © 2024 SwiftBSV developers
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import XCTest
@testable import SwiftBSV
import Foundation

class ScriptContextSurfaceTests: XCTestCase {

    func testStackIsPubliclySettable() {
        let context = ScriptExecutionContext()
        context.stack = [Data([0x05])]
        XCTAssertEqual(context.stack, [Data([0x05])])
        // Verify through the context's own read-back API, not just the raw array.
        XCTAssertTrue(context.bool(at: -1), "seeded value 0x05 must be truthy")
        XCTAssertEqual(try context.number(at: -1), 5, "seeded value 0x05 must decode as 5")
    }

    func testLoadTransactionContextArmsChecksig() throws {
        let signer = PrivateKey(data: Data(repeating: 0x01, count: 32), network: .mainnet)
        let recipient = PrivateKey(data: Data(repeating: 0x02, count: 32), network: .mainnet)

        let prevTxid = Data(repeating: 0xcd, count: 32)
        let utxo = TransactionOutput(
            value: 169_012_961,
            lockingScript: signer.publicKey.address.toTxOutputScript().data
        )

        let unsignedInput = TransactionInput(
            previousOutput: TransactionOutPoint(hash: prevTxid, index: 1),
            signatureScript: utxo.lockingScript,
            sequence: UInt32.max
        )
        let payOut = TransactionOutput(
            value: 50_000_000,
            lockingScript: recipient.publicKey.address.toTxOutputScript().data
        )
        let changeOut = TransactionOutput(
            value: 169_012_961 - 50_000_000 - 10_000_000,
            lockingScript: signer.publicKey.address.toTxOutputScript().data
        )
        let unsignedTx = Transaction(
            version: 1,
            inputs: [unsignedInput],
            outputs: [payOut, changeOut],
            lockTime: 0
        )

        let sighashType = SighashType.BSV.ALL
        let subScript = Script(data: utxo.lockingScript)!
        let derSig = unsignedTx.sign(
            privateKey: signer,
            sighashType: sighashType,
            nIn: 0,
            subScript: subScript,
            value: utxo.value
        )
        let wireSig = derSig + Data([UInt8(sighashType.sighash & 0xff)])

        let unlockScript = try Script()
            .appendData(wireSig)
            .appendData(signer.publicKey.toDer())
        let signedInput = TransactionInput(
            previousOutput: unsignedInput.previousOutput,
            signatureScript: unlockScript.data,
            sequence: UInt32.max
        )
        let signedTx = Transaction(
            version: 1,
            inputs: [signedInput],
            outputs: [payOut, changeOut],
            lockTime: 0
        )

        let context = ScriptExecutionContext()
        try context.pushToStack(Data([0x01]))
        XCTAssertTrue(
            context.loadTransactionContext(transaction: signedTx, utxoToVerify: utxo, inputIndex: 0),
            "arming a valid inputIndex must return true"
        )
        XCTAssertEqual(context.stack, [Data([0x01])], "arming must not clear the stack")

        try context.pushToStack(wireSig)
        try context.pushToStack(signer.publicKey.toDer())
        try OpCode.OP_CHECKSIG.execute(context)
        XCTAssertTrue(context.bool(at: -1), "OP_CHECKSIG must succeed after arming via loadTransactionContext")
    }

    func testLoadTransactionContextOutOfRangeIsNoOp() throws {
        let signer = PrivateKey(data: Data(repeating: 0x03, count: 32), network: .mainnet)

        let prevTxid = Data(repeating: 0xab, count: 32)
        let utxo = TransactionOutput(
            value: 1_000_000,
            lockingScript: signer.publicKey.address.toTxOutputScript().data
        )
        let input = TransactionInput(
            previousOutput: TransactionOutPoint(hash: prevTxid, index: 0),
            signatureScript: utxo.lockingScript,
            sequence: UInt32.max
        )
        let tx = Transaction(
            version: 1,
            inputs: [input],
            outputs: [],
            lockTime: 0
        )

        // Arm with a valid transaction first so we have known state.
        let context = ScriptExecutionContext()
        XCTAssertTrue(
            context.loadTransactionContext(transaction: tx, utxoToVerify: utxo, inputIndex: 0),
            "valid arm must return true"
        )
        XCTAssertEqual(context.utxoToVerify, utxo, "first arm must set utxoToVerify")

        // Now try to arm with an out-of-range inputIndex — must return false and leave state unchanged.
        let anotherUtxo = TransactionOutput(value: 999, lockingScript: Data())
        XCTAssertFalse(
            context.loadTransactionContext(transaction: tx, utxoToVerify: anotherUtxo, inputIndex: 5),
            "out-of-range inputIndex must return false"
        )
        XCTAssertEqual(context.utxoToVerify, utxo, "out-of-range inputIndex must not replace the armed utxo")
    }
}
